import re
from ast_engine import analyze_python_taint, analyze_enterprise_taint, GLOBAL_PROPAGATION_MAP

class DetectedSnippet:
    def __init__(self, file_path, line_number, snippet, context_above, context_below, pattern_type, code_slice=None, tainted_vars=None, function_name="global", vulnerable_syntax="", base_path=""):
        self.file_path = file_path
        self.line_number = line_number
        self.snippet = snippet
        self.context_above = context_above
        self.context_below = context_below
        self.pattern_type = pattern_type
        self.code_slice = code_slice
        self.tainted_vars = tainted_vars
        self.function_name = function_name
        self.vulnerable_syntax = vulnerable_syntax
        self.base_path = base_path

    def get_full_context(self):
        if self.code_slice:
            return "\n".join(self.code_slice)
        return "\n".join(self.context_above + [self.snippet] + self.context_below)

# Patterns categorized for precision filtering
PATTERNS = {
    'GENERAL': {
        # repoguard-ignore-next-line
        'Hardcoded Secret': r'(?i)(api[_-]?key|password|secret|token|apikey)\s*=\s*[\'"](?!test|dummy|example|placeholder|your_|my_|fake)[a-zA-Z0-9_\-\.\~]{8,}[\'"]',
        'SQL Injection Pattern': r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*|\b(execute|query)\(.*\+.*',
        'Unsafe Eval/Exec': r'(?i)(eval|exec)\(',
        'Command Execution': r'(?i)(os\.(system|popen)|subprocess\.(run|call|Popen|check_output|check_call)\()',
    },
    'AI_SPECIFIC': {
        # Tightened: only match .format or f-strings if 'prompt' or 'template' is in the line
        'Prompt Injection Risk': r'(?i)(prompt|template).*\.format\(|\.template\s*=|\.render\(|PromptTemplate\(|f[\'"].*(prompt|template).*\{[a-zA-Z_].*\}[\'"]|\{\{.*\}\}',
        # repoguard-ignore-next-line
        'Unsafe Tool/Agent Usage': r'ShellTool|PythonREPL|exec\(',
        # repoguard-ignore-next-line
        'Sensitive Data in Prompt': r'(?i)(prompt|template).*(password|secret|key|token|internal)',
        'Vector DB Risk': r'\.(add|upsert|insert)\(',
    }
}

AI_FRAMEWORK_PATTERNS = {
    'LangChain': r'langchain',
    'LlamaIndex': r'llama_index|llamaindex',
    'OpenAI': r'openai',
    'Anthropic': r'anthropic',
    'Transformers': r'transformers',
    'ChromaDB': r'chromadb',
    'Pinecone': r'pinecone',
    'Weaviate': r'weaviate',
    'FAISS': r'faiss'
}

VULN_METADATA = {
    'Hardcoded Secret': {
        'owasp': 'A07:2021-Identification and Authentication Failures',
        'cwe': 'CWE-798',
        'base_severity': 'High'
    },
    'SQL Injection Pattern': {
        'owasp': 'A03:2021-Injection',
        'cwe': 'CWE-89',
        'base_severity': 'Critical'
    },
    'Unsafe Eval/Exec': {
        'owasp': 'A03:2021-Injection',
        'cwe': 'CWE-94',
        'base_severity': 'Critical'
    },
    'Command Execution': {
        'owasp': 'A03:2021-Injection',
        'cwe': 'CWE-78',
        'base_severity': 'Critical'
    },
    'Prompt Injection Risk': {
        'owasp': 'LLM01:2023-Prompt Injection',
        'cwe': 'CWE-116',
        'base_severity': 'High'
    },
    'Unsafe Tool/Agent Usage': {
        'owasp': 'LLM08:2023-Excessive Agency',
        'cwe': 'CWE-250',
        'base_severity': 'Critical'
    },
    'Sensitive Data in Prompt': {
        'owasp': 'LLM06:2023-Sensitive Information Disclosure',
        'cwe': 'CWE-200',
        'base_severity': 'High'
    },
    'Vector DB Risk': {
        'owasp': 'A03:2021-Injection',
        'cwe': 'CWE-89',
        'base_severity': 'Medium'
    }
}

def detect_ai_stack(file_contents):
    """
    Identifies which AI frameworks are used in the project.
    """
    detected_frameworks = []
    # Join first few lines (usually imports) for faster detection
    imports_blob = "".join(file_contents[:50])
    for name, pattern in AI_FRAMEWORK_PATTERNS.items():
        if re.search(pattern, imports_blob, re.IGNORECASE):
            detected_frameworks.append(name)
    return detected_frameworks

def get_logical_context(lines, target_idx, file_path, min_context=15):
    """
    Dynamically extracts a logical code block for LLM context.
    Uses indentation-based detection for Python and brace-counting for Enterprise languages.
    """
    if not lines:
        return [], []
    
    ext = file_path.lower().split('.')[-1]
    is_brace_lang = ext in ('js', 'ts', 'jsx', 'tsx', 'java', 'go', 'cs', 'cpp', 'c')
    
    target_line = lines[target_idx]
    
    # Use simpler boundary hunting for brace languages as indentation can be inconsistent
    if is_brace_lang:
        start_idx = max(0, target_idx - min_context)
        # Scan upwards for a likely function/class start: {
        for i in range(target_idx, max(-1, target_idx - 30), -1):
            if '{' in lines[i] and ('function' in lines[i] or '(' in lines[i]):
                start_idx = i
                break
        
        end_idx = min(len(lines), target_idx + min_context)
        # Scan downwards for a likely block end: }
        open_braces = 0
        for i in range(start_idx, min(len(lines), target_idx + 40)):
            open_braces += lines[i].count('{')
            open_braces -= lines[i].count('}')
            if i > target_idx and open_braces <= 0:
                end_idx = i + 1
                break
    else:
        # Python-style indentation logic
        base_indent = len(target_line) - len(target_line.lstrip())
        start_idx = max(0, target_idx - min_context)
        for i in range(target_idx - 1, max(-1, target_idx - min_context * 2), -1):
            if lines[i].strip():
                indent = len(lines[i]) - len(lines[i].lstrip())
                if indent < base_indent and ("def " in lines[i] or "class " in lines[i]):
                    start_idx = i
                    break
                    
        end_idx = min(len(lines), target_idx + min_context)
        for i in range(target_idx + 1, min(len(lines), target_idx + min_context * 2)):
            if lines[i].strip():
                indent = len(lines[i]) - len(lines[i].lstrip())
                if indent < base_indent and i > target_idx + 5:
                    end_idx = i
                    break
                
    context_above = [l.strip() for l in lines[start_idx:target_idx]]
    context_below = [l.strip() for l in lines[target_idx+1:end_idx]]
    return context_above, context_below

def scan_file(file_path, lines, base_path="", context_lines=20):
    """
    Scans a file using AST (Python/JS/TS/Java/Go) or regex (fallback).
    """
    detections = []
    # Lines from read_file_content already contain newline characters.
    # Joining them with '' prevents doubling the newlines and skewing AST line numbers.
    source_code = "".join(lines)
    max_line = len(lines)
    ast_processed = False
    
    # 1. AST Analysis (Python)
    if file_path.endswith('.py'):
        try:
            ast_processed = True
            # [Fix #1]: Inter-Procedural Propagation awareness
            results = analyze_python_taint(file_path, source_code, GLOBAL_PROPAGATION_MAP)
            for r in results:
                if r.confidence == "Low":
                    continue # Heavently deprioritize or filter out generic parameter trace flow

                lineno = min(r.lineno, max_line)
                
                # [Fix #3]: Check for inline developer ignore directives
                current_line_text = lines[lineno - 1].lower() if lineno > 0 else ""
                prev_line_text = lines[lineno - 2].lower() if lineno > 1 else ""
                if 'repoguard-ignore-next-line' in prev_line_text or 'repoguard-ignore' in current_line_text:
                    continue

                detections.append(DetectedSnippet(
                    file_path=file_path,
                    line_number=lineno,
                    snippet=lines[lineno-1].strip() if lineno > 0 else "",
                    context_above=[], 
                    context_below=[],
                    pattern_type=r.sink_type,
                    code_slice=r.code_slice,
                    tainted_vars=r.tainted_vars,
                    function_name=r.function_name,
                    vulnerable_syntax=r.vulnerable_syntax,
                    base_path=base_path
                ))
        except Exception as e:
            from rich.console import Console as _C; _C().print(f"[dim]  (Python AST scan skipped for {file_path}: {e})[/dim]")
            ast_processed = False

    # 2. Enterprise AST Analysis (JS/TS/JSX/TSX/Java/Go)
    if file_path.endswith(('.js', '.ts', '.jsx', '.tsx', '.java', '.go')):
        try:
            ast_processed = True
            results = analyze_enterprise_taint(file_path, source_code)
            for r in results:
                if r.confidence == "Low":
                    continue # Filter out generic parameters

                lineno = min(r.lineno, max_line)
                
                # [Fix #3]: Check for inline developer ignore directives
                current_line_text = lines[lineno - 1].lower() if lineno > 0 else ""
                prev_line_text = lines[lineno - 2].lower() if lineno > 1 else ""
                if 'repoguard-ignore-next-line' in prev_line_text or 'repoguard-ignore' in current_line_text:
                    continue

                detections.append(DetectedSnippet(
                    file_path=file_path,
                    line_number=lineno,
                    snippet=lines[lineno-1].strip() if lineno > 0 else "",
                    context_above=[],
                    context_below=[],
                    pattern_type=r.sink_type,
                    code_slice=r.code_slice,
                    tainted_vars=r.tainted_vars,
                    function_name=r.function_name,
                    vulnerable_syntax=r.vulnerable_syntax,
                    base_path=base_path
                ))
        except Exception as e:
            from rich.console import Console as _C; _C().print(f"[dim]  (Enterprise AST scan skipped for {file_path}: {e})[/dim]")
            ast_processed = False

    # Detect AI stack once for the whole file
    ai_stack = detect_ai_stack(lines)
    has_ai_stack = len(ai_stack) > 0

    # 3. Regex Fallback with Structural Analysis
    in_block = False
    block_marker = None

    for i, line in enumerate(lines):
        clean_line = line.strip()
        
        # [Precision]: Lexical Boundary Tracking (Strings vs Comments)
        # We need to know if markers like /* or # are inside a string literal.
        if not in_block:
            # 1. Temporarily remove string literals from the line for structural analysis
            # This handles escaped quotes: \" or \'
            stripped_line = re.sub(r'"(?:\\.|[^"])*"|\'(?:\\.|[^\'])*\'', '""', line)
            
            # 2. Check for multi-line block starts in the string-stripped code
            if '"""' in stripped_line:
                in_block = True; block_marker = '"""'
            elif "'''" in stripped_line:
                in_block = True; block_marker = "'''"
            elif '/*' in stripped_line:
                in_block = True; block_marker = '/*'
            
            # Handle single-line docstrings or block comments: """ ... """
            if in_block:
                end_marker = '*/' if block_marker == '/*' else block_marker
                # We check the ORIGINAL line for the end marker, but ONLY after the start marker
                start_pos = line.find(block_marker)
                if line.find(end_marker, start_pos + len(block_marker)) != -1:
                    in_block = False; block_marker = None
        else:
            # We are inside a block, look for the closer
            end_marker = '*/' if block_marker == '/*' else block_marker
            if end_marker in line:
                in_block = False; block_marker = None
            continue # Always skip lines inside blocks

        if in_block:
            continue

        # [Fix #3]: Check for inline developer ignore directives for Regex
        current_line_text = line.lower()
        prev_line_text = lines[i - 1].lower() if i > 0 else ""
        if 'repoguard-ignore-next-line' in prev_line_text or 'repoguard-ignore' in current_line_text:
            continue
            
        # [Fix #2]: Robust comment stripping to prevent regex from flagging documentation
        # Handle #, //, and start of block comments
        clean_code = re.sub(r'(?:^\s*|\s+)(//|#).*$', '', clean_line).strip()
        
        if not clean_code or clean_code.startswith(('/*', '*', '"""', "'''")):
            continue
            
        # Iterate through General and AI-specific patterns
        for category, patterns in PATTERNS.items():
            # Skip AI patterns if no AI stack is detected in the file
            if category == 'AI_SPECIFIC' and not has_ai_stack:
                continue

            for ptype, pattern in patterns.items():
                # If the file was processed by AST, skip core risks already covered
                if ast_processed and ptype in ('SQL Injection Pattern', 'Command Execution', 'Unsafe Eval/Exec'):
                    continue
                    
                if re.search(pattern, clean_code):
                    # Smart layout boundary extraction
                    context_above, context_below = get_logical_context(lines, i, file_path, context_lines)
                    
                    detections.append(DetectedSnippet(
                        file_path=file_path,
                        line_number=i + 1,
                        snippet=clean_line,
                        context_above=context_above,
                        context_below=context_below,
                        pattern_type=ptype,
                        base_path=base_path
                    ))
                    break
    return detections
