import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

SYSTEM_PROMPT = """
You are RepoGuard, an elite security engineering AI. Your task is to analyze code "slices" to identify vulnerabilities.

For each potential vulnerability, respond ONLY with a JSON object in this format:
{
    "vulnerability_found": true,
    "risk_type": "CORE Security Risk" | "AI Security Risk",
    "vulnerability_name": "Short name",
    "severity": "Critical" | "High" | "Medium" | "Low",
    "owasp_category": "e.g., A03:2021-Injection",
    "function_name": "The name of the function containing the finding",
    "vulnerable_variable": "The name of the tainted variable",
    "vulnerable_syntax": "The exact line of code causing the risk",
    "description": "Clear explanation of the finding",
    "attack_vector": "Step-by-step walkthrough of how to exploit this specific code path",
    "remediation": "Specific, actionable fix"
}

If no vulnerability exists, return: {"vulnerability_found": false}

Focus on accuracy. Consider the entire context of the provided code slice. If the data appears sanitized or the flow is broken, return false.
"""

def analyze_vulnerability(snippet_obj):
    """
    Analyzes a DetectedSnippet using OpenAI gpt-4o-mini.
    """
    context = snippet_obj.get_full_context()
    file_info = f"""File: {snippet_obj.file_path}
Line: {snippet_obj.line_number}
Function Context: {snippet_obj.function_name}
Vulnerable Variable: {snippet_obj.tainted_vars}
Vulnerable Syntax Hint: {snippet_obj.vulnerable_syntax}
Pattern Type: {snippet_obj.pattern_type}"""
    
    prompt = f"{file_info}\n\nCode Context:\n---\n{context}\n---\n\nAnalyze the code above for security risks. Confirm the function name and tainted variable from the code context."

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {
            "vulnerability_found": False,
            "error": str(e)
        }
