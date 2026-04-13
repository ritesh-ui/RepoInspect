import re
from ast_engine import analyze_python_taint, analyze_enterprise_taint

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

# Basic regex patterns for initial filtering
PATTERNS = {
    'Hardcoded Secret': r'(?i)(api[_-]?key|password|secret|token|apikey)\s*=\s*[\'"][a-zA-Z0-9_\-\.\~]{8,}[\'"]',
    'SQL Injection Pattern': r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*|\b(execute|query)\(.*\+.*',
    'Unsafe Eval/Exec': r'(?i)(eval|exec)\(',
    'Command Execution': r'(?i)(os\.(system|popen)|subprocess\.(run|call|Popen|check_output|check_call)\(.*shell=True)',
    
    # AI/LLM Security Patterns
    'Prompt Injection Risk': r'(?i)\.format\(|f[\'"].*\{[a-zA-Z_][a-zA-Z0-9_]*\}[\'"]|\{\{.*\}\}|\{[a-zA-Z_][a-zA-Z0-9_]*\}|template\.render\(',
    'Unsafe Tool/Agent Usage': r'ShellTool|PythonREPL|exec\(',
    'Sensitive Data in Prompt': r'(?i)(prompt|template).*(password|secret|key|token|internal)',
    'Vector DB Risk': r'\.(add|upsert|insert)\(',
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

def get_logical_context(lines, target_idx, min_context=15):
    """Dynamically extracts a logical code block based on indentation for better LLM context."""
    if not lines:
        return [], []
    
    target_line = lines[target_idx]
    base_indent = len(target_line) - len(target_line.lstrip())
    
    start_idx = max(0, target_idx - min_context)
    for i in range(target_idx - 1, max(-1, target_idx - min_context * 2), -1):
        if lines[i].strip():
            indent = len(lines[i]) - len(lines[i].lstrip())
            if indent < base_indent and ("def " in lines[i] or "class " in lines[i] or "function " in lines[i]):
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
        ast_processed = True
        results = analyze_python_taint(file_path, source_code)
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

    # 2. Enterprise AST Analysis (JS/TS/JSX/TSX/Java/Go)
    if file_path.endswith(('.js', '.ts', '.jsx', '.tsx', '.java', '.go')):
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

    # 3. Regex Fallback
    for i, line in enumerate(lines):
        clean_line = line.strip()
        
        # [Fix #3]: Check for inline developer ignore directives for Regex
        current_line_text = line.lower()
        prev_line_text = lines[i - 1].lower() if i > 0 else ""
        if 'repoguard-ignore-next-line' in prev_line_text or 'repoguard-ignore' in current_line_text:
            continue
            
        # [Fix #2]: Strip comments to prevent regex from flagging documentation
        # Remove anything after // or # if it's preceded by whitespace or at the start of a line
        clean_code = re.sub(r'(?:^\s*|\s+)(//|#).*$', '', clean_line).strip()
        
        # Skip if the line is empty or purely a multiline comment start/end (basic heuristic)
        if not clean_code or clean_code.startswith('/*') or clean_code.startswith('*'):
            continue
            
        for ptype, pattern in PATTERNS.items():
            # If the file was processed by AST, do not let generic Regex second-guess its precision on core risks
            if ast_processed and ptype in ('SQL Injection Pattern', 'Command Execution', 'Unsafe Eval/Exec'):
                continue
                
            if re.search(pattern, clean_code):
                # [Fix #4]: Smart layout boundary extraction
                context_above, context_below = get_logical_context(lines, i, context_lines)
                
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
