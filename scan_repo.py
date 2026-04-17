import os
import argparse
import tempfile
import subprocess
from file_loader import get_repo_files, read_file_content
from scanner import scan_file, detect_ai_stack
from llm_analyzer import analyze_vulnerability
from reporter import report_findings_cli, report_findings_json, report_ai_stack, report_findings_markdown
from rich.console import Console

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

def run_scan(repo_path, json_output=None, markdown_output=None, limit=None):
    """Core scanning logic moved to a separate function for reusability."""
    # 1. Load files
    files = get_repo_files(repo_path)
    console.print(f"🔍 Found {len(files)} supported files.")

    all_findings = []
    
    # 2. Local pattern scan & AI Stack Detection
    console.print("⏳ Performing initial pattern scanning...")
    hotspots = []
    detected_frameworks = set()
    
    for file_path in files:
        lines = read_file_content(file_path)
        if lines:
            # Detect AI stack
            stack = detect_ai_stack(lines)
            detected_frameworks.update(stack)
            
            # Detect hotspots
            file_hotspots = scan_file(file_path, lines, base_path=repo_path)
            hotspots.extend(file_hotspots)
    
    # Report AI Stack
    ai_stack = sorted(list(detected_frameworks))
    if ai_stack:
        report_ai_stack(ai_stack)
    
    if not hotspots:
        console.print("[green]✅ No suspicious patterns found during initial scan.[/green]")
        return all_findings

    # 3. LLM analysis
    total_hotspots = len(hotspots)
    if limit and total_hotspots > limit:
        console.print(f"🔥 Found {total_hotspots} potential hotspots. [bold yellow]Limiting AI analysis to the first {limit} targets...[/bold yellow]")
        analysis_targets = hotspots[:limit]
    else:
        console.print(f"🔥 Found {total_hotspots} potential hotspots. Analyzing with AI...")
        analysis_targets = hotspots

    from concurrent.futures import ThreadPoolExecutor
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

    all_findings = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[yellow]AI Reasoning about vulnerabilities...", total=len(analysis_targets))
        
        def process_hotspot(hotspot):
            try:
                result = analyze_vulnerability(hotspot)
                progress.advance(task)
                return result, hotspot
            except Exception as e:
                progress.advance(task)
                return {"error": str(e)}, hotspot

        # Use a reasonable concurrency limit to avoid massive rate limits or thread bloat
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_results = list(executor.map(process_hotspot, analysis_targets))

        for result, hotspot in future_results:
            if result.get("vulnerability_found"):
                # Clean up file path if it's in a temp directory
                result["file"] = hotspot.file_path
                result["line"] = hotspot.line_number
                all_findings.append(result)
            elif "error" in result:
                console.print(f"[red]AI Error scanning {hotspot.file_path}: {result['error']}[/red]")

    # 4. Reporting
    report_findings_cli(all_findings)

    if json_output:
        report_findings_json(all_findings, json_output)
    
    if markdown_output:
        report_findings_markdown(all_findings, markdown_output, ai_stack)
    
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="RepoGuard: AI-Powered Repository Security Scanner")
    parser.add_argument("repo_path", help="Path or Git URL of the repository to scan")
    parser.add_argument("--json", help="Output findings to a JSON file", metavar="FILE")
    parser.add_argument("--markdown", help="Output findings to a Markdown file", metavar="FILE")
    parser.add_argument("--branch", help="Specific branch to scan (for remote repos)", metavar="BRANCH")
    parser.add_argument("--fail-on", help="Fail with exit code 1 if vulnerabilities of this severity or higher are found", 
                        choices=["Low", "Medium", "High", "Critical"], metavar="SEVERITY")
    parser.add_argument("--limit", type=int, help="Limit the number of AI-analyzed hotspots (useful for large repos)")
    args = parser.parse_args()

    repo_path = args.repo_path
    
    # Graceful check for API Key
    if not os.getenv("OPENAI_API_KEY"):
        console.print("\n" + "="*60, style="yellow")
        console.print("⚠️  WARNING: OPENAI_API_KEY NOT FOUND", style="bold yellow")
        console.print("="*60, style="yellow")
        console.print("RepoGuard's Deep AI Analysis is disabled.")
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
                findings = run_scan(temp_dir, args.json, args.markdown, args.limit)
            else:
                sys.exit(1)
    else:
        if not os.path.isdir(repo_path):
            console.print(f"[red]Error: {repo_path} is not a valid directory or Git URL.[/red]")
            sys.exit(1)
        
        console.print(f"[bold blue]🚀 Starting scan on:[/bold blue] {repo_path}")
        findings = run_scan(repo_path, args.json, args.markdown, args.limit)

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
    import sys
    main()
