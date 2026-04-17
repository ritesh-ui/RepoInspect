import ast
from tree_sitter_languages import get_parser
from dataclasses import dataclass
from typing import List, Set, Dict, Optional

# Known sanitizer functions that break the taint chain
SANITIZER_FUNCTIONS = {
    # General sanitization
    'sanitize', 'escape', 'clean', 'purify', 'strip_tags',
    # URL/HTML encoding
    'urlencode', 'quote', 'quote_plus', 'html_escape', 'markupsafe',
    # Python-specific
    'bleach_clean', 'escape_string', 'parameterize',
    # Django — NOTE: mark_safe is explicitly EXCLUDED — it is a security bypass, not a sanitizer
    'escapejs', 'force_escape',
    # SQL parameterization helpers
    'mogrify', 'literal', 'escape_sql',
    # Numeric casts break injection chains for numeric contexts only
    # str/bool intentionally EXCLUDED — they are type-casts, not sanitizers
    'int', 'float',
}

# Explicit Untrusted Source identifiers used to assign High confidence
UNTRUSTED_SOURCES = {
    # Python
    'sys.argv', 'os.environ', 'request', 'request.args', 'request.form',
    'request.values', 'request.json', 'flask.request', 'django.request',
    'request.GET', 'request.POST', 'input',
    # JS/TS
    'req.body', 'req.query', 'req.params', 'process.env', 'process.argv',
    'request.body', 'request.query',
    # Java
    'request.getParameter', 'System.getenv', 'request.getHeader',
    # Go
    'r.URL.Query', 'r.FormValue', 'os.Getenv', 'os.Args'
}

# Identifier fragments used by TreeSitter scanner to assign High confidence
# (when any tainted variable name contains one of these keywords it's likely user input)
UNTRUSTED_VAR_HINTS = {
    'user', 'input', 'request', 'req', 'query', 'param', 'body', 'form',
    'arg', 'argv', 'env', 'environ', 'data', 'payload', 'cmd', 'command',
    'raw', 'unsafe', 'unvalidated', 'untrusted', 'external', 'remote',
}

# Qualified sink definitions: maps method names to the caller objects that make them dangerous
# Format: 'method_name': { 'risk_type': str, 'dangerous_callers': set | None }
# If dangerous_callers is None, the method is ALWAYS dangerous (e.g., eval, exec, os.system)
SCOPED_SINKS = {
    # Command Injection sinks — only dangerous on subprocess/os
    'system':       {'risk_type': 'Command Injection', 'dangerous_callers': {'os'}},
    'popen':        {'risk_type': 'Command Injection', 'dangerous_callers': {'os'}},
    'run':          {'risk_type': 'Command Injection', 'dangerous_callers': {'subprocess'}},
    'Popen':        {'risk_type': 'Command Injection', 'dangerous_callers': {'subprocess'}},
    'call':         {'risk_type': 'Command Injection', 'dangerous_callers': {'subprocess'}},
    'check_output': {'risk_type': 'Command Injection', 'dangerous_callers': {'subprocess'}},
    'check_call':   {'risk_type': 'Command Injection', 'dangerous_callers': {'subprocess'}},
    # SQL Injection sinks — only dangerous on db cursors/connections
    'execute':      {'risk_type': 'SQL Injection', 'dangerous_callers': {'cursor', 'conn', 'connection', 'db', 'session', 'engine', 'cur'}},
    'executemany':  {'risk_type': 'SQL Injection', 'dangerous_callers': {'cursor', 'conn', 'connection', 'db', 'session', 'cur'}},
    # Unsafe Eval — always dangerous regardless of caller
    'eval':         {'risk_type': 'Unsafe Eval', 'dangerous_callers': None},
    'exec':         {'risk_type': 'Unsafe Eval', 'dangerous_callers': None},
}

@dataclass
class TaintFlow:
    sink_node: any # ast.AST or tree_sitter.Node
    tainted_vars: List[str]
    code_slice: List[str]
    sink_type: str
    lineno: int
    sink_type: str
    lineno: int
    function_name: str = "global"
    vulnerable_syntax: str = ""
    confidence: str = "Low"

class ASTScanner(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.source_lines = source_code.splitlines()
        self.tainted_vars = set()
        self.explicit_sources = set()  # High confidence tainted vars
        self.findings: List[TaintFlow] = []
        self.current_func = "global"
        self.imported_modules = set()  # Track imports for scope awareness
        self._detect_imports(source_code)

    def _detect_imports(self, source_code: str):
        """Pre-scan imports to understand which dangerous modules are in scope."""
        try:
            tree = ast.parse(source_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.imported_modules.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        self.imported_modules.add(node.module.split('.')[0])
        except SyntaxError:
            pass

    def is_sink(self, node: ast.Call) -> Optional[str]:
        """Checks if a call node is a dangerous sink using scoped caller analysis.
        
        Instead of matching bare method names, this inspects the caller object
        to distinguish subprocess.run (dangerous) from thread.run (safe),
        or cursor.execute (dangerous) from task.execute (safe).
        """
        func_name = ""
        caller_name = ""
        
        if isinstance(node.func, ast.Name):
            # Bare call: eval(...), exec(...)
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Method call: subprocess.run(...), cursor.execute(...)
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                caller_name = node.func.value.id
            elif isinstance(node.func.value, ast.Attribute):
                # Chained: self.cursor.execute(...)
                caller_name = node.func.value.attr
        
        if not func_name:
            return None
        
        sink_def = SCOPED_SINKS.get(func_name)
        if not sink_def:
            return None
        
        dangerous_callers = sink_def['dangerous_callers']
        
        # If dangerous_callers is None, the function is ALWAYS dangerous (eval, exec)
        if dangerous_callers is None:
            return sink_def['risk_type']
        
        # If it's a bare call (no caller), check if the dangerous module is imported
        # e.g., `from subprocess import run; run(cmd, shell=True)`
        if not caller_name:
            module_for_func = None
            if func_name in ('system', 'popen'):
                module_for_func = 'os'
            elif func_name in ('run', 'Popen', 'call', 'check_output', 'check_call'):
                module_for_func = 'subprocess'
            if module_for_func and module_for_func in self.imported_modules:
                return sink_def['risk_type']
            return None
        
        # Scoped check: caller must match a known dangerous caller
        if caller_name.lower() in {c.lower() for c in dangerous_callers}:
            return sink_def['risk_type']
        
        return None

    def get_slice(self, start_lineno: int, end_lineno: int) -> List[str]:
        """Extracts lines of code from the source."""
        # Line numbers in AST are 1-indexed
        return self.source_lines[max(0, start_lineno-5):end_lineno+2]

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze each function independently (Intra-function)."""
        old_func = self.current_func
        self.current_func = node.name
        
        # Clear/Track taint for a new function scope
        old_taint = self.tainted_vars.copy()
        old_explicit = self.explicit_sources.copy()
        
        # Entry points: Function arguments are considered tainted (but Low Confidence)
        for arg in node.args.args:
            self.tainted_vars.add(arg.arg)
        
        # Visit children
        self.generic_visit(node)
        
        # Restore state
        self.tainted_vars = old_taint
        self.explicit_sources = old_explicit
        self.current_func = old_func

    def _is_sanitizer_call(self, node) -> bool:
        """Check if a call node invokes a known sanitizer function."""
        if not isinstance(node, ast.Call):
            return False
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        return func_name.lower() in SANITIZER_FUNCTIONS

    def visit_Assign(self, node: ast.Assign):
        """Track data flow through assignments with sanitizer awareness.
        
        If the RHS is a call to a known sanitizer function (e.g., escape(), sanitize()),
        the taint chain is BROKEN — the assigned variable is considered clean.
        """
        # Check if RHS is a direct sanitizer call: safe_val = sanitize(user_input)
        if isinstance(node.value, ast.Call) and self._is_sanitizer_call(node.value):
            # Sanitizer detected — do NOT propagate taint. 
            # Also remove previously tainted vars if they are being reassigned.
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.discard(target.id)
                    self.explicit_sources.discard(target.id)
            self.generic_visit(node)
            return

        is_rh_tainted = False
        is_explicit_source = False
        
        for sub_node in ast.walk(node.value):
            if isinstance(sub_node, ast.Name):
                if sub_node.id in self.tainted_vars:
                    is_rh_tainted = True
                if sub_node.id in self.explicit_sources or sub_node.id in UNTRUSTED_SOURCES:
                    is_rh_tainted = True
                    is_explicit_source = True
            elif isinstance(sub_node, ast.Attribute):
                attr_name = f"{sub_node.value.id}.{sub_node.attr}" if isinstance(sub_node.value, ast.Name) else sub_node.attr
                if attr_name in UNTRUSTED_SOURCES:
                    is_rh_tainted = True
                    is_explicit_source = True
            elif isinstance(sub_node, ast.Call) and isinstance(sub_node.func, ast.Name) and sub_node.func.id in UNTRUSTED_SOURCES:
                is_rh_tainted = True
                is_explicit_source = True
        
        if is_rh_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
                    if is_explicit_source:
                        self.explicit_sources.add(target.id)
        
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Detect when tainted data reaches a sink with precision logic."""
        risk_type = self.is_sink(node)
        if risk_type:
            # 1. Specialized Precision for Command Injection
            if risk_type == 'Command Injection':
                func_name = ""
                if isinstance(node.func, ast.Name): func_name = node.func.id
                elif isinstance(node.func, ast.Attribute): func_name = node.func.attr

                # Rule: subprocess.* is safe if it uses a list and shell is not enabled
                if func_name in ['run', 'Popen', 'call', 'check_output', 'check_call']:
                    is_shell = False
                    for kw in node.keywords:
                        if kw.arg == 'shell':
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                is_shell = True
                    
                    # If shell=False (default) and first arg is a list OR uses *args, it's relatively safe
                    if not is_shell:
                        if node.args and isinstance(node.args[0], (ast.List, ast.Starred)):
                            # This is the "Safe List Execution" pattern requested by the user
                            self.generic_visit(node)
                            return

            # 2. General Taint Analysis
            tainted_args = []
            for arg in node.args:
                for sub_node in ast.walk(arg):
                    if isinstance(sub_node, ast.Name) and sub_node.id in self.tainted_vars:
                        tainted_args.append(sub_node.id)
            
            for kw in node.keywords:
                for sub_node in ast.walk(kw.value):
                    if isinstance(sub_node, ast.Name) and sub_node.id in self.tainted_vars:
                        tainted_args.append(sub_node.id)

            if tainted_args:
                code_slice = self.get_slice(node.lineno-5, node.lineno)
                syntax = "Unknown"
                try:
                    syntax = self.source_lines[node.lineno-1].strip()
                except: pass

                confidence = "High" if any(arg in self.explicit_sources for arg in tainted_args) else "Low"

                self.findings.append(TaintFlow(
                    sink_node=node,
                    tainted_vars=list(set(tainted_args)),
                    code_slice=code_slice,
                    sink_type=risk_type,
                    lineno=node.lineno,
                    function_name=self.current_func,
                    vulnerable_syntax=syntax,
                    confidence=confidence
                ))
        
        self.generic_visit(node)

def analyze_python_taint(file_path: str, code: str) -> List[TaintFlow]:
    """Helper to run the AST scanner on a file."""
    try:
        tree = ast.parse(code)
        scanner = ASTScanner(code)
        scanner.visit(tree)
        return scanner.findings
    except SyntaxError:
        return []

class TreeSitterScanner:
    """Universal scanner for JS/TS using Tree-Sitter."""
    def __init__(self, language: str, source_code: str):
        self.language = language
        self.source_lines = source_code.splitlines()
        self.source_bytes = source_code.encode('utf-8')
        self.parser = get_parser(language)
        self.tainted_vars = set()
        self.findings: List[TaintFlow] = []
        self.current_func = "global"
        
        # Language-specific definitions
        self.language_config = {
            'javascript': {
                'sinks': ['exec', 'execSync', 'spawn', 'spawnSync', 'query', 'execute', 'raw', 'create', 'run', 'invoke', 'predict', 'upsert', 'eval', 'Function'],
                'funcs': ('function_declaration', 'arrow_function', 'method_definition'),
                'assigns': ('assignment_expression', 'variable_declarator')
            },
            'typescript': {
                'sinks': ['exec', 'execSync', 'spawn', 'spawnSync', 'query', 'execute', 'raw', 'create', 'run', 'invoke', 'predict', 'upsert', 'eval', 'Function'],
                'funcs': ('function_declaration', 'arrow_function', 'method_definition'),
                'assigns': ('assignment_expression', 'variable_declarator')
            },
            'java': {
                'sinks': ['exec', 'start', 'execute', 'executeQuery', 'executeUpdate', 'createNativeQuery', 'create', 'run'],
                'funcs': ('method_declaration', 'constructor_declaration'),
                'assigns': ('assignment_expression', 'variable_declarator')
            },
            'go': {
                'sinks': ['Command', 'Query', 'Exec', 'QueryRow', 'Get', 'Post'],
                'funcs': ('function_declaration', 'method_declaration'),
                'assigns': ('assignment_statement', 'short_var_declaration')
            }
        }
        
        config = self.language_config.get(language, self.language_config['javascript'])
        self.sink_list = config['sinks']
        self.func_types = config['funcs']
        self.assign_types = config['assigns']

    def get_slice(self, start_row: int, end_row: int) -> List[str]:
        """Extracts lines of code from source."""
        return self.source_lines[max(0, start_row-5):end_row+2]

    def is_sink(self, func_name: str, caller_name: str = "") -> Optional[str]:
        categories = {
            'Command Injection': {
                'funcs': ['exec', 'execSync', 'spawn', 'spawnSync', 'start', 'Command', 'start', 'run'],
                'dangerous_callers': {'child_process', 'os', 'Runtime', 'ProcessBuilder', 'exec', 'syscall', 'exec.Command'}
            },
            'SQL Injection': {
                'funcs': ['query', 'execute', 'raw', 'executeQuery', 'executeUpdate', 'createNativeQuery', 'Query', 'Exec', 'QueryRow'],
                'dangerous_callers': {'db', 'conn', 'connection', 'cursor', 'statement', 'stmt', 'session', 'tx', 'entityManager', 'sql', 'sqlx'}
            },
            'AI Security Risk': {
                'funcs': ['create', 'run', 'invoke', 'predict', 'upsert'],
                'dangerous_callers': {'openai', 'agent', 'llm', 'chain', 'model', 'anthropic', 'pinecone', 'milvus'}
            },
            'Unsafe Eval': {
                'funcs': ['eval', 'Function'],
                'dangerous_callers': None
            }
        }
        for cat, config in categories.items():
            if func_name in config['funcs']:
                if config['dangerous_callers'] is None:
                    return cat
                
                # For Enterprise languages (Java/Go), we require a caller to be present and match a heuristic
                # This prevents flagging a local helper function named 'execute' or 'run'
                if self.language in ('java', 'go'):
                    if caller_name and any(c in caller_name.lower() for c in config['dangerous_callers']):
                        return cat
                    return None
                
                # For JavaScript, we are more aggressive due to dynamic naming/imports
                if caller_name:
                    if any(c in caller_name.lower() for c in config['dangerous_callers']):
                        return cat
                    return None
                else:
                    # Bare name call in JS (e.g. const { exec } = require...)
                    return cat
        return None

    def trace_node(self, node):
        """Recursively traverse Tree-Sitter nodes to find taint and sinks."""
        
        # 1. Detect Entry Points & Update Function Context
        if node.type in self.func_types:
            # Capture Name
            name_node = node.child_by_field_name('name')
            old_func = self.current_func
            old_tainted = self.tainted_vars.copy()
            
            if name_node:
                self.current_func = name_node.text.decode('utf-8')

            params = node.child_by_field_name('parameters') or node.child_by_field_name('parameter_list')
            if params:
                stack = [params]
                while stack:
                    curr = stack.pop()
                    if curr.type == 'identifier':
                        self.tainted_vars.add(curr.text.decode('utf-8'))
                    stack.extend(curr.children)
            
            # Recurse and then restore
            for child in node.children:
                self.trace_node(child)
            
            self.current_func = old_func
            self.tainted_vars = old_tainted
            return

        # 2. Detect Taint Propagation (Assignments)
        if node.type in self.assign_types:
            left = node.child_by_field_name('left') or node.child_by_field_name('name')
            if not left and node.type in ('assignment_statement', 'short_var_declaration'):
                children = node.children
                if len(children) >= 3:
                    left = children[0]
                    right = children[2]
            else:
                right = node.child_by_field_name('right') or node.child_by_field_name('value')
            
            if left and right:
                is_tainted = False
                is_sanitizer = False
                
                # Check if RHS is a sanitizer call
                if right.type in ('call_expression', 'method_invocation'):
                    fn = right.child_by_field_name('function') or right.child_by_field_name('name')
                    if fn:
                        fname = ""
                        if fn.type in ('member_expression', 'field_access', 'selector_expression'):
                            prop = fn.child_by_field_name('property') or fn.child_by_field_name('name') or fn.child_by_field_name('field')
                            if prop: fname = prop.text.decode('utf-8')
                        else:
                            fname = fn.text.decode('utf-8')
                        if fname.lower() in SANITIZER_FUNCTIONS:
                            is_sanitizer = True
                
                if is_sanitizer:
                    stack = [left]
                    while stack:
                        curr = stack.pop()
                        if curr.type == 'identifier':
                            self.tainted_vars.discard(curr.text.decode('utf-8'))
                        stack.extend(curr.children)
                else:
                    stack = [right]
                    while stack:
                        curr = stack.pop()
                        if curr.type == 'identifier' and curr.text.decode('utf-8') in self.tainted_vars:
                            is_tainted = True
                        if curr.type == 'call_expression':
                            fn = curr.child_by_field_name('function')
                            if fn and b'Sprintf' in fn.text:
                                is_tainted = True
                        stack.extend(curr.children)
                    
                    if is_tainted:
                        stack = [left]
                        while stack:
                            curr = stack.pop()
                            if curr.type == 'identifier':
                                self.tainted_vars.add(curr.text.decode('utf-8'))
                            stack.extend(curr.children)

        # 3. Detect Sinks (Calls & Constructor Creation)
        call_types = ('call_expression', 'method_invocation', 'object_creation_expression')
        if node.type in call_types:
            func_node = node.child_by_field_name('function') or node.child_by_field_name('name') or node.child_by_field_name('type')
            if func_node:
                func_name = ""
                caller_name = ""
                if func_node.type in ('member_expression', 'field_access', 'selector_expression'):
                    # Object caller
                    obj = func_node.child_by_field_name('object') or func_node.child_by_field_name('operand')
                    if obj: caller_name = obj.text.decode('utf-8').split('.')[0] # grab base generic name
                    
                    prop = func_node.child_by_field_name('property') or func_node.child_by_field_name('name') or func_node.child_by_field_name('field')
                    if prop: func_name = prop.text.decode('utf-8')
                else:
                    func_name = func_node.text.decode('utf-8')
                
                risk_type = self.is_sink(func_name, caller_name)
                if not risk_type and b'ProcessBuilder' in func_node.text:
                    risk_type = 'Command Injection'

                if risk_type:
                    args = node.child_by_field_name('arguments') or node.child_by_field_name('argument_list')
                    if args:
                        tainted_found = []
                        stack = [args]
                        while stack:
                            curr = stack.pop()
                            if curr.type == 'identifier' and curr.text.decode('utf-8') in self.tainted_vars:
                                tainted_found.append(curr.text.decode('utf-8'))
                            stack.extend(curr.children)
                        
                        if tainted_found:
                            syntax = "Unknown"
                            try:
                                syntax = self.source_lines[node.start_point[0]].strip()
                            except: pass

                            # Assign confidence: High if any tainted var name hints at user input
                            # This fixes the critical bug where all enterprise findings defaulted to Low
                            var_names_lower = {v.lower() for v in tainted_found}
                            confidence = "High" if any(
                                hint in vname
                                for hint in UNTRUSTED_VAR_HINTS
                                for vname in var_names_lower
                            ) else "Low"

                            self.findings.append(TaintFlow(
                                sink_node=node,
                                tainted_vars=list(set(tainted_found)),
                                code_slice=self.get_slice(node.start_point[0], node.end_point[0]),
                                sink_type=risk_type,
                                lineno=node.start_point[0] + 1,
                                function_name=self.current_func,
                                vulnerable_syntax=syntax,
                                confidence=confidence
                            ))

        # Recurse
        for child in node.children:
            self.trace_node(child)

def analyze_enterprise_taint(file_path: str, code: str) -> List[TaintFlow]:
    """Helper to run the Tree-Sitter scanner on JS/TS/Java/Go files."""
    ext_map = {
        '.js': 'javascript', '.jsx': 'javascript',
        '.ts': 'typescript', '.tsx': 'typescript',
        '.java': 'java',
        '.go': 'go'
    }
    
    ext = next((e for e in ext_map if file_path.endswith(e)), None)
    if not ext: return []
    
    lang = ext_map[ext]
    try:
        scanner = TreeSitterScanner(lang, code)
        tree = scanner.parser.parse(code.encode('utf-8'))
        scanner.trace_node(tree.root_node)
        return scanner.findings
    except Exception as e:
        return []

# Legacy export for scanner.py compatibility
def analyze_js_taint(file_path: str, code: str) -> List[TaintFlow]:
    return analyze_enterprise_taint(file_path, code)
