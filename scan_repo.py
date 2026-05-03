import os
import sys
import argparse
import tempfile
import subprocess
from file_loader import get_repo_files, read_file_content
from scanner import scan_file, detect_ai_stack, VULN_METADATA
from llm_analyzer import analyze_vulnerability, analyze_vulnerabilities_batch
from ast_engine import run_taint_pre_pass_single, merge_propagation_maps, GLOBAL_PROPAGATION_MAP
from reporter import report_findings_cli, report_findings_json, report_ai_stack, report_findings_markdown
from report_generator import generate_enterprise_report
try:
    from rag_indexer import init_rag_indexer
except ImportError:
    init_rag_indexer = None
from rich.console import Console
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

console = Console()

def is_git_url(path):
    """Checks if the path is a git URL."""
    return path.startswith(('https://', 'http://', 'git@', 'ssh://'))

def clone_repo(repo_url, temp_dir, branch=None):
    """Clones a git repository into a temporary directory."""
    console.print(f"[bold yellow]⏳ Cloning repository:[/bold yellow] {repo_url}")
    command = ["git", "clone", "--depth", "1"]
    if branch:
        command.extend(["--branch", branch])
    command.extend([repo_url, temp_dir])
    
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ Error cloning repository:[/red] {e.stderr}")
        return False

def init_worker(prop_map):
    """Initializer for worker processes to set up global state once."""
    import ast_engine
    if prop_map:
        deserialized_map = {k: {'tainted_indices': set(v['tainted_indices'])} for k, v in prop_map.items()}
        ast_engine.GLOBAL_PROPAGATION_MAP.clear()
        ast_engine.GLOBAL_PROPAGATION_MAP.update(deserialized_map)

def process_file_patterns(file_arg):
    """Helper for parallel pattern scanning.
    Receives (file_path, repo_path) as a single tuple.
    Uses the global propagation map initialized in the worker.
    """
    file_path, repo_path = file_arg
    
    lines = read_file_content(file_path)
    if not lines: return [], set()
    
    stack = detect_ai_stack(lines)
    hotspots = scan_file(file_path, lines, base_path=repo_path)
    return hotspots, set(stack)

def run_scan(repo_path, json_output=None, markdown_output=None, html_output=None, limit=None, max_workers=None):
    """Core scanning logic with Parallelism and Batching."""
    # 1. Load files
    files = get_repo_files(repo_path)
    console.print(f"🔍 Found {len(files)} supported files.")

    # 2. Global Taint Discovery (Pass 1 - Parallel)
    console.print("⏳ Building Inter-Procedural Taint Map (Pass 1 - Parallel)...")
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        local_maps = list(executor.map(run_taint_pre_pass_single, files))
    
    global GLOBAL_PROPAGATION_MAP
    GLOBAL_PROPAGATION_MAP.clear()
    GLOBAL_PROPAGATION_MAP.update(merge_propagation_maps(local_maps))
    
    if GLOBAL_PROPAGATION_MAP:
        console.print(f"🔗 Identified {len(GLOBAL_PROPAGATION_MAP)} potential cross-function propagators.")

    # 2.5 Build Semantic AST-Aware GraphRAG Index
    if init_rag_indexer:
        init_rag_indexer(repo_path, files)

    # 3. Local pattern scan (Pass 2 - Parallel)
    console.print("⏳ Performing deep pattern scanning (Pass 2 - Parallel)...")
    hotspots = []
    detected_frameworks = set()
    
    # [Performance Boost]: Pass the propagation map ONCE via initializer
    # to avoid 9,000+ redundant pickling/unpickling operations.
    serializable_map = {k: {'tainted_indices': list(v['tainted_indices'])} for k, v in GLOBAL_PROPAGATION_MAP.items()}
    file_args = [(f, repo_path) for f in files]
    
    with ProcessPoolExecutor(max_workers=max_workers, initializer=init_worker, initargs=(serializable_map,)) as executor:
        results = list(executor.map(process_file_patterns, file_args))
    
    for h_list, f_set in results:
        hotspots.extend(h_list)
        detected_frameworks.update(f_set)
    
    # Report AI Stack
    ai_stack = sorted(list(detected_frameworks))
    if ai_stack:
        report_ai_stack(ai_stack)
    
    all_findings = []

    if not hotspots:
        console.print("[green]✅ No suspicious patterns found during initial scan.[/green]")
        return all_findings

    # 4. AI Analysis (Batching Mode)
    total_hotspots = len(hotspots)
    if limit and total_hotspots > limit:
        console.print(f"🔥 Found {total_hotspots} potential hotspots. [bold yellow]Limiting AI analysis to the first {limit} targets...[/bold yellow]")
        analysis_targets = hotspots[:limit]
    else:
        console.print(f"🔥 Found {total_hotspots} potential hotspots. Analyzing with AI (Batched)...")
        analysis_targets = hotspots

    
    # Group findings by file for efficient batching context
    by_file = {}
    for h in analysis_targets:
        if h.file_path not in by_file: by_file[h.file_path] = []
        by_file[h.file_path].append(h)

    # Convert to flat list of batches (max 5 per batch)
    batches = []
    for file_path, items in by_file.items():
        for i in range(0, len(items), 5):
            batches.append(items[i:i+5])

    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[yellow]AI Reasoning (Batch Mode)...", total=len(batches))
        
        def process_batch(batch):
            try:
                # If only one item, use the smarter Agent loop
                if len(batch) == 1:
                    result = analyze_vulnerability(batch[0])
                    results = [result]
                else:
                    # If multiple, use the faster batch mode
                    results = analyze_vulnerabilities_batch(batch)
                
                progress.advance(task)
                return results, batch
            except Exception as e:
                progress.advance(task)
                return [{"error": str(e)} for _ in batch], batch

        # I/O bound calls to OpenAI — ThreadPool is fine here
        with ThreadPoolExecutor(max_workers=3) as executor:
            batch_results = list(executor.map(process_batch, batches))

        for results, batch in batch_results:
            # Handle results being a single dict if LLM ignored array instruction for N=1
            if isinstance(results, dict) and not isinstance(results, list):
                results = [results]
                
            for i, result in enumerate(results):
                if i >= len(batch): break # Guard
                
                if not isinstance(result, dict):
                    continue
                    
                if result.get("vulnerability_found"):
                    hotspot = batch[i]
                    # Apply deterministic metadata
                    metadata = VULN_METADATA.get(hotspot.pattern_type, {})
                    
                    # Smart Pathing: Calculate path relative to CWD for better workspace context
                    try:
                        result["file"] = os.path.relpath(hotspot.file_path, os.getcwd())
                    except ValueError:
                        result["file"] = os.path.relpath(hotspot.file_path, repo_path)
                    result["line"] = hotspot.line_number
                    # Favor AST-detected qualified function name if AI result is generic
                    ai_func = str(result.get("function_name", "")).lower()
                    if ai_func in ("unknown", "global", "n/a", ""):
                        result["function_name"] = hotspot.function_name
                    
                    result["severity"] = metadata.get("base_severity", result.get("severity", "High"))
                    result["owasp_category"] = metadata.get("owasp", "N/A")
                    result["cwe"] = metadata.get("cwe", "N/A")
                    
                    all_findings.append(result)
                elif "error" in result:
                    console.print(f"[red]Batch Error: {result['error']}[/red]")

    # 4. Reporting
    report_findings_cli(all_findings)

    if json_output:
        report_findings_json(all_findings, json_output)
    
    if markdown_output:
        report_findings_markdown(all_findings, markdown_output, ai_stack)

    if html_output:
        generate_enterprise_report(all_findings, html_output, target_repo=repo_path, ai_stack=ai_stack)
    
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="RepoInspect: AI-Powered Repository Security Scanner")
    parser.add_argument("repo_path", help="Path or Git URL of the repository to scan")
    parser.add_argument("--json", help="Output findings to a JSON file", metavar="FILE")
    parser.add_argument("--markdown", help="Output findings to a Markdown file", metavar="FILE")
    parser.add_argument("--html", help="Output a professional Enterprise HTML report", metavar="FILE")
    parser.add_argument("--branch", help="Specific branch to scan (for remote repos)", metavar="BRANCH")
    parser.add_argument("--fail-on", help="Fail with exit code 1 if vulnerabilities of this severity or higher are found", 
                        choices=["Low", "Medium", "High", "Critical"], metavar="SEVERITY")
    parser.add_argument("--limit", type=int, help="Limit the number of AI-analyzed hotspots (useful for large repos)")
    parser.add_argument("--ollama", action="store_true", help="Use local Ollama instance (localhost:11434)")
    parser.add_argument("--lmstudio", action="store_true", help="Use local LM Studio instance (localhost:1234)")
    parser.add_argument("--local-model", help="Specify local model name (e.g. llama3)")
    args = parser.parse_args()

    repo_path = args.repo_path
    
    # Local Provider Setup
    if args.ollama:
        os.environ["REPOINSPECT_LOCAL_PROVIDER"] = "ollama"
        if args.local_model: os.environ["LOCAL_MODEL"] = args.local_model
    elif args.lmstudio:
        os.environ["REPOINSPECT_LOCAL_PROVIDER"] = "lmstudio"
        if args.local_model: os.environ["LOCAL_MODEL"] = args.local_model

    # Pre-flight health check for local providers
    local_provider = os.environ.get("REPOINSPECT_LOCAL_PROVIDER")
    if local_provider:
        import urllib.request
        port = "11434" if local_provider == "ollama" else "1234"
        # LM Studio exposes v1/models, Ollama base URL returns 200
        url = f"http://localhost:{port}/v1/models" if local_provider == "lmstudio" else f"http://localhost:{port}"
        
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                pass # Success
            console.print(f"[bold green]✅ Local AI Detected ({local_provider.upper()})[/bold green]")
            console.print(f"💡 Tip: For high-precision auditing, we recommend 'llama3'.")
        except Exception:
            console.print(f"\n[bold red]⚠️  ERROR: {local_provider.upper()} NOT DETECTED[/bold red]")
            console.print(f"Please ensure {local_provider.upper()} is running on port {port} before starting a local scan.")
            sys.exit(1)

    # Graceful check for API Key (skipped if local provider is used)
    if not local_provider and not os.getenv("OPENAI_API_KEY"):
        console.print("\n" + "="*60, style="yellow")
        console.print("⚠️  WARNING: OPENAI_API_KEY NOT FOUND", style="bold yellow")
        console.print("="*60, style="yellow")
        console.print("RepoInspect's Deep AI Analysis is disabled.")
        console.print("To enable full AST-based security auditing and attack vector")
        console.print("analysis, please set your OPENAI_API_KEY in your environment")
        console.print("or as a GitHub Secret.")
        console.print("="*60 + "\n", style="yellow")
        console.print("🚀 Running Fast Pattern-Only Scan...\n")

    findings = []
    if is_git_url(repo_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            if clone_repo(repo_path, temp_dir, args.branch):
                console.print(f"[bold blue]🚀 Starting scan on remote repo...[/bold blue]")
                findings = run_scan(temp_dir, args.json, args.markdown, args.html, args.limit)
            else:
                sys.exit(1)
    else:
        if not os.path.isdir(repo_path):
            console.print(f"[red]Error: {repo_path} is not a valid directory or Git URL.[/red]")
            sys.exit(1)
        
        console.print(f"[bold blue]🚀 Starting scan on:[/bold blue] {repo_path}")
        findings = run_scan(repo_path, args.json, args.markdown, args.html, args.limit)

    # Exit code logic for CI/CD
    if args.fail_on:
        severity_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        threshold = severity_map.get(args.fail_on, 0)
        
        highest_severity = 0
        for f in findings:
            sev_level = severity_map.get(f.get("severity"), 0)
            if sev_level > highest_severity:
                highest_severity = sev_level
        
        if highest_severity >= threshold:
            console.print(f"\n[bold red]❌ Scan failed: Found vulnerabilities with severity {args.fail_on} or higher.[/bold red]")
            sys.exit(1)
        else:
            console.print(f"\n[bold green]✅ Scan passed: No vulnerabilities found at or above {args.fail_on} severity.[/bold green]")

if __name__ == "__main__":
    main()
