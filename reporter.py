import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()

SEVERITY_COLORS = {
    "Critical": "bold red on white",
    "High": "bold red",
    "Medium": "bold yellow",
    "Low": "bold blue"
}

def report_ai_stack(frameworks):
    """
    Prints a summary of the detected AI stack.
    """
    if frameworks:
        stack_str = ", ".join(frameworks)
        console.print(Panel(f"[bold cyan]🤖 AI Stack Detected:[/bold cyan] {stack_str}", expand=False))

def report_findings_cli(findings):
    """
    Prints findings in a professional CLI format.
    """
    if not findings:
        console.print("[bold green]✅ No vulnerabilities found![/bold green]")
        return

    table = Table(title="RepoGuard Security Findings")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta")
    table.add_column("Category", style="yellow")
    table.add_column("Vulnerability", style="bold white")
    table.add_column("Severity", style="bold")

    for f in findings:
        severity = f.get("severity", "Low")
        color = SEVERITY_COLORS.get(severity, "white")
        table.add_row(
            f["file"],
            str(f["line"]),
            f.get("owasp_category", "N/A"),
            f.get("vulnerability_name", "Unknown"),
            f"[{color}]{severity}[/{color}]"
        )
    
    console.print(table)
    console.print("\n[bold]Detailed Attack Vectors:[/bold]\n")

    for f in findings:
        severity = f.get("severity", "Low")
        color = SEVERITY_COLORS.get(severity, "white")
        risk_type = f.get("risk_type", "CORE")
        vuln_name = f.get("vulnerability_name", "Unknown")
        
        panel_content = f"""[bold]File:[/bold] {f['file']}
[bold]Line:[/bold] {f['line']}
[bold]OWASP Category:[/bold] {f.get('owasp_category', 'N/A')}
[bold]Vulnerability:[/bold] {vuln_name}
[bold]Severity:[/bold] [{color}]{severity}[/{color}]
[bold]Attack Vector:[/bold]
{f.get('attack_vector', 'N/A')}

[bold]Description:[/bold] {f['description']}
[bold]Remediation:[/bold] {f['remediation']}
"""
        console.print(Panel(panel_content.strip(), expand=False))

def report_findings_json(findings, output_file):
    """
    Saves findings to a JSON file.
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=4)
        console.print(f"\n[green]Report saved to {output_file}[/green]")
    except Exception as e:
        console.print(f"\n[red]Error saving JSON report: {e}[/red]")

def report_findings_markdown(findings, output_file, ai_stack=None):
    """
    Saves findings as a professional Markdown report.
    """
    try:
        with open(output_file, 'w') as f:
            f.write("# 🛡️ RepoGuard Security Report\n\n")
            
            if ai_stack:
                stack_str = ", ".join(ai_stack)
                f.write(f"### 🤖 AI Stack Detected: `{stack_str}`\n\n")
            
            if not findings:
                f.write("> [!SUCCESS]\n")
                f.write("> No security vulnerabilities were identified in the scanned codebase.\n\n")
            else:
                f.write("## 📊 Summary\n\n")
                f.write("| File | Line | OWASP | Vulnerability | Severity |\n")
                f.write("| :--- | :--- | :--- | :--- | :--- |\n")
                for fn in findings:
                    severity = fn.get("severity", "Low")
                    f.write(f"| {fn['file']} | {fn['line']} | {fn.get('owasp_category', 'N/A')} | {fn.get('vulnerability_name', 'Unknown')} | **{severity}** |\n")
                
                f.write("\n---\n\n")
                f.write("## 🔍 Detailed Attack Vectors\n\n")
                for fn in findings:
                    severity = fn.get("severity", "Low")
                    f.write(f"### 📍 {fn.get('vulnerability_name', 'Vulnerability')} in `{fn['file']}`\n")
                    f.write(f"- **Line**: {fn['line']}\n")
                    f.write(f"- **OWASP Category**: {fn.get('owasp_category', 'N/A')}\n")
                    f.write(f"- **Severity**: {severity}\n\n")
                    f.write(f"> **Description**: {fn['description']}\n\n")
                    f.write(f"#### 🏹 Attack Vector\n{fn.get('attack_vector', 'N/A')}\n\n")
                    f.write(f"#### 🛠 Remediation\n{fn['remediation']}\n\n")
                    f.write("---\n\n")
                    
        console.print(f"\n[green]Markdown report saved to {output_file}[/green]")
    except Exception as e:
        console.print(f"\n[red]Error saving Markdown report: {e}[/red]")
