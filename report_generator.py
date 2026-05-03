import os
import json
import datetime

# High-end Enterprise Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RepoInspect | Forensic Audit Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0a0c10;
            --card-bg: #161b22;
            --border: #30363d;
            --text-main: #c9d1d9;
            --text-bright: #ffffff;
            --accent-blue: #58a6ff;
            --accent-purple: #bc8cff;
            --critical: #ff7b72;
            --high: #ffa657;
            --medium: #d29922;
            --low: #3fb950;
            --glass: rgba(255, 255, 255, 0.05);
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            background-color: var(--bg); 
            color: var(--text-main); 
            font-family: 'Inter', sans-serif; 
            padding: 60px 40px;
            line-height: 1.6;
        }}

        .container {{ max-width: 1100px; margin: 0 auto; }}

        /* --- Header --- */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 30px;
            margin-bottom: 60px;
        }}

        .logo {{ 
            font-weight: 800; 
            font-size: 1.8rem; 
            color: var(--text-bright); 
            letter-spacing: -1px;
        }}
        .logo span {{ color: var(--accent-blue); }}
        
        .report-meta {{ 
            text-align: right; 
            font-size: 0.9rem; 
            color: var(--text-main);
            opacity: 0.8;
        }}

        /* --- Executive Summary --- */
        .summary-box {{
            background: linear-gradient(135deg, #161b22, #0d1117);
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 50px;
            border: 1px solid var(--border);
            box-shadow: 0 20px 50px rgba(0,0,0,0.3);
            position: relative;
            overflow: hidden;
        }}

        .summary-box::before {{
            content: '';
            position: absolute;
            top: 0; right: 0;
            width: 200px; height: 200px;
            background: radial-gradient(circle, rgba(88,166,255,0.1) 0%, transparent 70%);
        }}

        .summary-box h1 {{ 
            color: var(--text-bright); 
            font-size: 2.8rem; 
            margin-bottom: 15px;
            font-weight: 800;
        }}
        
        .target-info {{
            display: flex;
            gap: 30px;
            margin-bottom: 30px;
            font-size: 1.1rem;
        }}
        
        .target-info strong {{ color: var(--accent-blue); }}

        .stats-grid {{ 
            display: grid; 
            grid-template-columns: repeat(4, 1fr); 
            gap: 20px; 
            margin-top: 30px; 
        }}
        
        .stat-item {{ 
            padding: 20px; 
            border-radius: 12px; 
            background: var(--glass); 
            border: 1px solid var(--border);
            text-align: center;
        }}
        
        .stat-label {{ 
            font-size: 0.75rem; 
            text-transform: uppercase; 
            letter-spacing: 1.5px; 
            margin-bottom: 8px;
            font-weight: 600;
        }}
        
        .stat-value {{ font-size: 2.2rem; font-weight: 800; }}

        /* --- Finding Cards --- */
        .finding-card {{
            background: var(--card-bg);
            border-radius: 16px;
            border: 1px solid var(--border);
            padding: 40px;
            margin-bottom: 40px;
            transition: all 0.3s;
        }}
        
        .finding-card:hover {{
            border-color: var(--accent-blue);
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}

        .finding-header {{ 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 25px; 
        }}
        
        .finding-title {{ font-size: 1.6rem; font-weight: 800; color: var(--text-bright); }}
        
        .badge {{
            padding: 6px 16px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .badge-critical {{ background: rgba(255, 123, 114, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(255, 166, 87, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(210, 153, 34, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background: rgba(63, 185, 80, 0.2); color: var(--low); border: 1px solid var(--low); }}

        .location {{ 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 0.9rem; 
            color: var(--accent-blue); 
            margin-bottom: 25px; 
            display: block; 
            opacity: 0.9;
        }}

        .section-header {{ 
            font-weight: 800; 
            color: var(--text-bright); 
            margin-bottom: 12px; 
            display: block; 
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .syntax-block {{
            background: #010409;
            padding: 20px;
            border-radius: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95rem;
            margin-bottom: 30px;
            border-left: 4px solid var(--accent-blue);
            color: #d1d5da;
            overflow-x: auto;
            white-space: pre;
        }}

        .finding-description {{ margin-bottom: 30px; font-size: 1.05rem; opacity: 0.95; }}

        .remediation {{
            background: rgba(88, 166, 255, 0.05);
            border: 1px solid rgba(88, 166, 255, 0.2);
            padding: 25px;
            border-radius: 12px;
        }}

        footer {{ 
            text-align: center; 
            padding: 60px 0; 
            font-size: 0.85rem; 
            opacity: 0.6; 
            border-top: 1px solid var(--border); 
            margin-top: 80px; 
        }}

        @media print {{
            body {{ padding: 0; background: white; color: black; }}
            .finding-card {{ break-inside: avoid; border: 1px solid #ddd; page-break-after: always; }}
            .summary-box {{ background: #f5f5f5; color: black; border: 1px solid #ddd; }}
            .syntax-block {{ background: #f8f8f8; color: black; border: 1px solid #ddd; }}
            .badge {{ border: 1px solid black; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">Repo<span>Inspect</span> Forensic</div>
            <div class="report-meta">
                ID: RI-{report_id}<br>
                Date: {date}<br>
                Status: Final Audit
            </div>
        </header>

        <section class="summary-box">
            <h1>Executive Security Summary</h1>
            <div class="target-info">
                <div>Target: <strong>{target_repo}</strong></div>
                <div>AI Stack: <strong>{ai_stack}</strong></div>
            </div>
            
            <p>This report contains a deep-dive forensic analysis of potential security vulnerabilities detected in the repository infrastructure. All findings have been verified via RepoInspect's AST-Aware Security Engine.</p>

            <div class="stats-grid">
                <div class="stat-item"><div class="stat-label" style="color: var(--critical)">Critical</div><span class="stat-value" style="color: var(--critical)">{count_critical}</span></div>
                <div class="stat-item"><div class="stat-label" style="color: var(--high)">High</div><span class="stat-value" style="color: var(--high)">{count_high}</span></div>
                <div class="stat-item"><div class="stat-label" style="color: var(--medium)">Medium</div><span class="stat-value" style="color: var(--medium)">{count_medium}</span></div>
                <div class="stat-item"><div class="stat-label" style="color: var(--low)">Low</div><span class="stat-value" style="color: var(--low)">{count_low}</span></div>
            </div>
        </section>

        <section class="findings">
            {findings_html}
        </section>

        <footer>
            &copy; 2026 RepoInspect Security. Branded Forensic Report.<br>
            For private audits, contact riteshsingh545@gmail.com
        </footer>
    </div>
</body>
</html>
"""

FINDING_HTML = """
<div class="finding-card">
    <div class="finding-header">
        <div class="finding-title">{name}</div>
        <div class="badge badge-{severity_class}">{severity}</div>
    </div>
    <span class="location">Location: {file} (Line {line})</span>

    <span class="section-header">Forensic Evidence</span>
    <div class="syntax-block">{syntax}</div>

    <span class="section-header">Description & Analysis</span>
    <p class="finding-description">
        {description}<br><br>
        <strong>Attack Vector:</strong> {attack_vector}
    </p>

    <div class="remediation">
        <span class="section-header" style="color: var(--accent-blue)">🛡 Recommended Remediation</span>
        <p>{remediation}</p>
    </div>
</div>
"""

def generate_enterprise_report(findings, output_path, target_repo="Target Repository", ai_stack=None):
    """
    Generates a high-end HTML forensic report.
    """
    import random
    import os
    import tomli # Using standard lib or simple parsing
    
    # Smart Project Name Discovery
    project_name = "Target Repository"
    try:
        # If target_repo is a path, try to find a name
        if os.path.isdir(target_repo):
            # Try pyproject.toml
            pyproject = os.path.join(target_repo, "pyproject.toml")
            if os.path.exists(pyproject):
                with open(pyproject, "r") as f:
                    for line in f:
                        if line.startswith("name ="):
                            project_name = line.split("=")[1].strip().replace('"', '').replace("'", "")
                            break
            # Try package.json
            if project_name == "Target Repository":
                pkg_json = os.path.join(target_repo, "package.json")
                if os.path.exists(pkg_json):
                    import json
                    with open(pkg_json, "r") as f:
                        data = json.load(f)
                        project_name = data.get("name", project_name)
            
            # Fallback to folder name
            if project_name == "Target Repository":
                project_name = os.path.basename(os.path.abspath(target_repo))
        else:
            project_name = target_repo
    except Exception:
        project_name = target_repo

    report_id = str(random.randint(1000, 9999))
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    findings_list_html = []

    # Sort findings by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "Low"), 4))

    for f in sorted_findings:
        severity = f.get("severity", "Low")
        counts[severity] = counts.get(severity, 0) + 1
        
        findings_list_html.append(FINDING_HTML.format(
            name=f.get("vulnerability_name", "Vulnerability"),
            severity=severity,
            severity_class=severity.lower(),
            file=f.get("file", "Unknown"),
            line=f.get("line", "0"),
            syntax=f.get("vulnerable_syntax", "N/A"),
            description=f.get("description", "N/A"),
            attack_vector=f.get("attack_vector", "N/A"),
            remediation=f.get("remediation", "N/A")
        ))

    stack_str = ", ".join(ai_stack) if ai_stack else "Python / AI Infrastructure"
    
    final_html = HTML_TEMPLATE.format(
        report_id=report_id,
        date=datetime.date.today().strftime("%B %d, %Y"),
        target_repo=project_name,
        ai_stack=stack_str,
        count_critical=counts["Critical"],
        count_high=counts["High"],
        count_medium=counts["Medium"],
        count_low=counts["Low"],
        findings_html="".join(findings_list_html)
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(final_html)
    
    print(f"✅ Enterprise Report generated: {output_path}")
    return output_path
