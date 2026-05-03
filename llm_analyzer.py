import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Local Provider Routing Logic
LOCAL_PROVIDER = os.environ.get("REPOINSPECT_LOCAL_PROVIDER")
if LOCAL_PROVIDER == "ollama":
    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    MODEL = os.environ.get("LOCAL_MODEL", "llama3")
elif LOCAL_PROVIDER == "lmstudio":
    client = OpenAI(base_url="http://localhost:1234/v1", api_key="lmstudio")
    MODEL = os.environ.get("LOCAL_MODEL", "local-model")
else:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# Models known to support the { "type": "json_object" } response_format.
# This avoids brittle substring checks like 'gpt-4 in MODEL'.
_JSON_MODE_MODELS = {'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-4-1106-preview', 'gpt-3.5-turbo-1106'}

def _supports_json_mode(model_name: str) -> bool:
    """Check if a model supports OpenAI's structured JSON response mode."""
    # Local providers often struggle with forced JSON mode flags; 
    # we favor prompt coercion for maximum stability.
    if os.environ.get("REPOINSPECT_LOCAL_PROVIDER"):
        return False

    # Exact match first
    if model_name in _JSON_MODE_MODELS:
        return True
    # Prefix match for versioned variants (e.g., gpt-4o-2024-05-13)
    return any(model_name.startswith(base) for base in _JSON_MODE_MODELS)

# Inject strictness for local models
STRICT_JSON_RULE = "\nCRITICAL: Your response must be EXACTLY one valid JSON array/object. Do NOT include any preamble, markdown code blocks (```json), or post-response commentary. Your entire output will be directly piped into a strict JSON parser." if os.environ.get("REPOINSPECT_LOCAL_PROVIDER") else ""

SYSTEM_PROMPT = f"""
You are RepoInspect, an elite Autonomous Security Auditor. Eliminate false positives by tracing code paths.{STRICT_JSON_RULE}

YOUR DECISION LOGIC:
1. FIRST, analyze the provided code context carefully.
2. If the vulnerability is UNAMBIGUOUSLY CLEAR from the provided snippet (e.g., shell=True is present, eval(user_input) is directly visible), conclude IMMEDIATELY. Do NOT use tools — just return your JSON verdict.
3. ONLY use tools if the vulnerability is AMBIGUOUS because the variable's origin is unclear and comes from another file or a helper function you haven't seen. Tools are expensive — use them sparingly.
4. If your tool investigation reveals adequate upstream sanitization or that the data is not user-controlled, return {{"vulnerability_found": false}}.
5. [PLACEHOLDER AWARENESS]: Explicitly identify obvious placeholder or test values in 'Hardcoded Secret' findings. If a value CONTAINS 'YOUR', 'test', 'dummy', 'example', 'placeholder', or 'fake', or if it appears in a test file (e.g., in /tests/ directory) and looks like a dummy string, return {{"vulnerability_found": false}}.
6. [TEST-SCOPE AWARENESS]: Findings in test files (e.g., in /tests/ or test_*.py) are almost always false positives unless they are clearly vulnerable to external influence. If a finding is in a unit test using static/mock data, return {{"vulnerability_found": false}}.
7. [SQL PARAMETERIZATION AWARENESS]: For SQL Injection, strictly distinguish between safe parameterized inputs and unsafe string interpolation. Variables passed as a tuple/list to the execution method (e.g., `execute(query, (var1, var2))`) are SAFE. Do NOT flag them. If the query string itself is constructed using f-strings, `.format()`, or `%` (e.g., `f"UPDATE {{table}}..."`), the variables injected *into the string* (like `table`) are the TRUE vulnerabilities. If the originally flagged variable is safe but the string interpolation is unsafe, change the 'vulnerable_variable' to the interpolated one. If ALL variables are safely parameterized and no string interpolation exists, return {{"vulnerability_found": false}}.
8. [COMMAND INJECTION AWARENESS]: If the vulnerability is Command Execution, explicitly check if the command is passed as a LIST of strings to `subprocess.Popen`, `subprocess.run`, or `subprocess.call` (e.g., `subprocess.Popen(['python', 'script.py', user_input])`). If it is a list and `shell=True` is NOT explicitly set, the OS protects against shell injection. This is SAFE. Return {{"vulnerability_found": false}}.
9. [VARIADIC ARGS DELEGATION AWARENESS]: A common safe pattern is a thin wrapper function that collects arguments via `*args: str` and delegates them to `subprocess.run(args, ...)`. If you see `subprocess.run(variable, ...)` where `variable` is the function's own `*args` parameter (typed as `str`), use tools to inspect the call sites of that wrapper. If ALL call sites pass ONLY hardcoded string literals (not user-controlled input) as the variadic args, this is SAFE delegation — NOT command injection. Return {{"vulnerability_found": false}}. NOTE: This rule does NOT apply if any call site passes a variable derived from user input, environment variables, or external data into the variadic arguments.
10. [ARGPARSE CLI CREDENTIAL AWARENESS]: Do NOT flag `LLM06: Sensitive Information Disclosure` or `Sensitive Data Exposure` when the pattern is: a user explicitly provides a credential (e.g., `--api-key`, `--token`, `--password`) via `argparse` CLI arguments, and that credential is then passed as a parameter to a function call. This is by-design behavior — the user IS the source and the consumer of their own credential. There is no third-party exposure. Return {{"vulnerability_found": false}}. CRITICAL EXCEPTION: This rule does NOT apply if the argparse value flows into a SQL query, shell command construction, file path, or log output. If `args.api_key` is being used to construct an f-string SQL query or shell command, that IS a vulnerability and must still be flagged.
11. [SAFE DESERIALIZATION AWARENESS]: If `pickle.load` or `yaml.unsafe_load` is loading a file with a hardcoded path (e.g., `open('config.pkl')`) or a known local asset within the project, it is SAFE. Only flag if the source data is derived from user input, network data, or an external blob. If the context shows the data comes from a trusted internal state, return {{"vulnerability_found": false}}.
12. [XSS IN LLM OUTPUT AWARENESS]: For `innerHTML` or `dangerouslySetInnerHTML`, only flag if the data being rendered is derived from an LLM response or user input. If it is a static string or internal UI state, it is SAFE. Return {{"vulnerability_found": false}}.

Respond ONLY with a JSON array when multiple findings are provided, or a single JSON object for one finding.
Format:
[
  {{
      "finding_id": "unique_id_from_input",
      "vulnerability_found": true,
      "risk_type": "CORE Security Risk" | "AI Security Risk",
      "vulnerability_name": "Short name",
      "function_name": "The name of the function",
      "vulnerable_variable": "The name of the variable",
      "vulnerable_syntax": "The exact line of code causing the risk",
      "description": "Clear explanation",
      "attack_vector": "Step-by-step walkthrough",
      "remediation": "Specific fix"
  }},
  ...
]

If no vulnerability exists for a specific ID, still include it in the array with: {{"finding_id": "...", "vulnerability_found": false}}
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
        retry_count = 0
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

                    from rich.console import Console as _C; _C().print(f"  [dim]↳ Agent: tracing via [italic]{function_name}[/italic]...[/dim]")

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
                    # Clean up common LLM noise
                    if "```json" in content:
                        content = content.split("```json")[-1].split("```")[0].strip()
                    elif "```" in content:
                        content = content.split("```")[-1].split("```")[0].strip()
                    return json.loads(content)
                except json.JSONDecodeError as e:
                    if retry_count < 2:
                        retry_count += 1
                        messages.append({
                            "role": "user", 
                            "content": f"Your previous output was invalid JSON. Error: {str(e)}. Please fix the syntax and return ONLY raw JSON."
                        })
                        continue
                    return {"vulnerability_found": False, "error": f"JSON Parse Error: {str(e)}"}

        # Hit max turns — force a final verdict using all accumulated context
        # This prevents false negatives when obvious vulnerabilities are present
        return _force_final_verdict(messages)
    except Exception as e:
        return {"vulnerability_found": False, "error": str(e)}

def analyze_vulnerabilities_batch(snippets):
    """
    Analyzes multiple hotspots in a single LLM turn to save tokens and time. 
    Groups them by file context for maximum shared reasoning efficiency.
    """
    if not snippets: return []
    
    # 1. Prepare batched prompt
    targets_info = []
    for i, snip in enumerate(snippets):
        targets_info.append(f"""
FINDING ID: {i}
File: {snip.file_path}
Line: {snip.line_number}
Context: {snip.function_name}
Tainted Vars: {snip.tainted_vars}
Syntax: {snip.vulnerable_syntax}
Category: {snip.pattern_type}
Code snippet:
{snip.get_full_context()}
---""")

    batch_prompt = "\n".join(targets_info)
    prompt = (
        f"You are evaluating {len(snippets)} potential security hotspots in a batch. "
        "Analyze each one carefully. If a finding is a false positive, mark it as found: false. "
        "Respond ONLY with a JSON array containing your verdicts for ALL findings.\n\n"
        f"BATCH TARGETS:\n{batch_prompt}"
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt}
    ]

    try:
        retry_count = 0
        while retry_count <= 2:
            response = client.chat.completions.create(
                model=MODEL,
                messages=messages,
                response_format={"type": "json_object"} if _supports_json_mode(MODEL) else None
            )
            content = response.choices[0].message.content or "[]"
            
            # Clean up common LLM noise
            if "```json" in content:
                content = content.split("```json")[-1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[-1].split("```")[0].strip()
            
            try:
                # Open AI sometimes returns { "findings": [...] } instead of raw array if forced to json_object
                data = json.loads(content)
                
                # Normalize result to a list
                results_list = []
                if isinstance(data, dict):
                    if "findings" in data and isinstance(data["findings"], list):
                        results_list = data["findings"]
                    else:
                        results_list = [data]
                elif isinstance(data, list):
                    results_list = data
                    
                return results_list
            except json.JSONDecodeError as e:
                if retry_count < 2:
                    retry_count += 1
                    messages.append({"role": "assistant", "content": content})
                    messages.append({
                        "role": "user", 
                        "content": f"Your previous output was invalid JSON. Error: {str(e)}. Please fix the syntax and return ONLY raw JSON."
                    })
                    continue
                raise e

    except Exception as e:
        return [{"vulnerability_found": False, "error": str(e)} for _ in snippets]
