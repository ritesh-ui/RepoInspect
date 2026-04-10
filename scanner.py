import re
from ast_engine import analyze_python_taint, analyze_js_taint

class DetectedSnippet:
    def __init__(self, file_path, line_number, snippet, context_above, context_below, pattern_type, code_slice=None, tainted_vars=None):
        self.file_path = file_path
        self.line_number = line_number
        self.snippet = snippet
        self.context_above = context_above
        self.context_below = context_below
        self.pattern_type = pattern_type
        self.code_slice = code_slice
        self.tainted_vars = tainted_vars

    def get_full_context(self):
        if self.code_slice:
            return "\n".join(self.code_slice)
        return "\n".join(self.context_above + [self.snippet] + self.context_below)

# Basic regex patterns for initial filtering
PATTERNS = {
    'Hardcoded Secret': r'(?i)(api[_-]?key|password|secret|token|apikey)\s*=\s*[\'"][a-zA-Z0-9_\-\.\~]{8,}[\'"]',
    'SQL Injection Pattern': r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*|\b(execute|query)\(.*\+.*',
    'Unsafe Eval/Exec': r'(?i)(eval|exec)\(',
    'Command Execution': r'(?i)(os\.system|subprocess\.(run|call|Popen|check_output))\(',
    
    # AI/LLM Security Patterns
    'Prompt Injection Risk': r'(?i)\.format\(|f[\'"].*\{[a-zA-Z_][a-zA-Z0-9_]*\}[\'"]|\{\{.*\}\}|\{[a-zA-Z_][a-zA-Z0-9_]*\}|template\.render\(',
    'Unsafe Tool/Agent Usage': r'ShellTool|PythonREPL|exec\(|subprocess|os\.system',
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

def scan_file(file_path, lines, context_lines=10):
    """
    Scans a file using AST (Python/JS/TS) or regex (fallback).
    """
    detections = []
    source_code = "\n".join(lines)
    
    # 1. AST Analysis (Python)
    if file_path.endswith('.py'):
        results = analyze_python_taint(file_path, source_code)
        for r in results:
            detections.append(DetectedSnippet(
                file_path=file_path,
                line_number=r.lineno,
                snippet=lines[r.lineno-1].strip() if r.lineno <= len(lines) else "",
                context_above=[], 
                context_below=[],
                pattern_type=r.sink_type,
                code_slice=r.code_slice,
                tainted_vars=r.tainted_vars
            ))
        if detections: return detections

    # 2. AST Analysis (JS/TS/JSX/TSX)
    if file_path.endswith(('.js', '.ts', '.jsx', '.tsx')):
        results = analyze_js_taint(file_path, source_code)
        for r in results:
            detections.append(DetectedSnippet(
                file_path=file_path,
                line_number=r.lineno,
                snippet=lines[r.lineno-1].strip() if r.lineno <= len(lines) else "",
                context_above=[],
                context_below=[],
                pattern_type=r.sink_type,
                code_slice=r.code_slice,
                tainted_vars=r.tainted_vars
            ))
        if detections: return detections

    # 3. Regex Fallback
    for i, line in enumerate(lines):
        clean_line = line.strip()
        for ptype, pattern in PATTERNS.items():
            if re.search(pattern, clean_line):
                start_context = max(0, i - context_lines)
                end_context = min(len(lines), i + context_lines + 1)
                
                context_above = [l.strip() for l in lines[start_context:i]]
                context_below = [l.strip() for l in lines[i+1:end_context]]
                
                detections.append(DetectedSnippet(
                    file_path=file_path,
                    line_number=i + 1,
                    snippet=clean_line,
                    context_above=context_above,
                    context_below=context_below,
                    pattern_type=ptype
                ))
                break
    return detections
