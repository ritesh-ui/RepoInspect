import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

SYSTEM_PROMPT = """
You are RepoGuard, an elite Autonomous Security Auditor. Eliminate false positives by tracing code paths.

YOUR DECISION LOGIC:
1. FIRST, analyze the provided code context carefully.
2. If the vulnerability is UNAMBIGUOUSLY CLEAR from the provided snippet (e.g., shell=True is present, eval(user_input) is directly visible), conclude IMMEDIATELY. Do NOT use tools — just return your JSON verdict.
3. ONLY use tools if the vulnerability is AMBIGUOUS because the variable's origin is unclear and comes from another file or a helper function you haven't seen. Tools are expensive — use them sparingly.
4. If your tool investigation reveals adequate upstream sanitization or that the data is not user-controlled, return {"vulnerability_found": false}.

Respond ONLY with a JSON object in this format when finished:
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

If no vulnerability exists (or you found upstream sanitization), return: {"vulnerability_found": false}
"""

from agent_tools import AGENT_TOOLS, execute_tool

def _force_final_verdict(messages: list) -> dict:
    """Force a final verdict from the LLM using all accumulated context, without tools."""
    messages_copy = list(messages)
    messages_copy.append({
        "role": "user",
        "content": "You have exhausted your tool-use budget. Based on EVERYTHING you have gathered so far, make your final determination and respond ONLY with the required JSON object."
    })
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages_copy,
            tool_choice="none",  # Force direct text answer
        )
        content = response.choices[0].message.content or ""
        if content.startswith("```json"):
            content = content.strip("`").removeprefix("json").strip()
        return json.loads(content)
    except Exception:
        return {"vulnerability_found": False, "error": "Forced verdict failed."}


def analyze_vulnerability(snippet_obj, max_turns=5):
    """
    Analyzes a DetectedSnippet using an Autonomous Auditing loop with tools.
    The Agent first checks if the vulnerability is obvious. Only if ambiguous
    does it invoke tools to trace the variable's origin cross-file.
    """
    context = snippet_obj.get_full_context()
    file_info = f"""File: {snippet_obj.file_path}
Line: {snippet_obj.line_number}
Function Context: {snippet_obj.function_name}
Potentially Tainted Variables: {snippet_obj.tainted_vars}
Syntax of Interest: {snippet_obj.vulnerable_syntax}
Security Category to Evaluate: {snippet_obj.pattern_type}"""

    prompt = (
        f"{file_info}\n\nCode Context:\n---\n{context}\n---\n\n"
        "Step 1: Determine if the vulnerability is UNAMBIGUOUSLY clear from the provided context above. "
        "If so, return your verdict immediately without using any tools. "
        "Step 2: If the variable's origin is UNCLEAR (defined in another file or a helper function not shown), "
        "use your tools to investigate — but keep tool usage minimal and targeted."
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt}
    ]

    try:
        turn_count = 0
        while turn_count < max_turns:
            response = client.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=AGENT_TOOLS,
                tool_choice="auto",
            )

            response_message = response.choices[0].message
            messages.append(response_message)

            if response_message.tool_calls:
                # Execute each tool call and feed results back
                for tool_call in response_message.tool_calls:
                    function_name = tool_call.function.name
                    function_args = tool_call.function.arguments

                    print(f"\n[AGENT] Tracing payload... (Executing internal tool: {function_name})")

                    tool_result = execute_tool(function_name, function_args, snippet_obj.base_path)

                    messages.append({
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "name": function_name,
                        "content": str(tool_result),
                    })
                turn_count += 1
            else:
                # No more tool calls — final output
                content = response_message.content or ""
                try:
                    if content.startswith("```json"):
                        content = content.strip("`").removeprefix("json").strip()
                    return json.loads(content)
                except json.JSONDecodeError:
                    return {"vulnerability_found": False, "error": "LLM did not return valid JSON"}

        # Hit max turns — force a final verdict using all accumulated context
        # This prevents false negatives when obvious vulnerabilities are present
        return _force_final_verdict(messages)

    except Exception as e:
        return {
            "vulnerability_found": False,
            "error": str(e)
        }
