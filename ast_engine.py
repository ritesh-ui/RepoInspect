import ast
from dataclasses import dataclass
from typing import List, Set, Dict, Optional, Union

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
    # Python Web Framework Entrypoints
    'request', 'request.args', 'request.form', 'request.values', 
    'request.json', 'request.files', 'request.headers',
    'flask.request', 'django.request', 'request.GET', 'request.POST',
    'input', 'sys.argv', 'os.environ',
    # JS/TS
    'req.body', 'req.query', 'req.params', 'request.body', 'request.query',
    'process.env', 'process.argv',
    # Java/Go
    'request.getParameter', 'System.getenv', 'r.URL.Query', 'os.Getenv'
}

# Identifier fragments used to assign High confidence.
# These are matched as WHOLE WORDS (not substrings) to avoid false positives
# from names like 'metadata', 'target', 'environment_config', etc.
import re as _re
UNTRUSTED_VAR_HINTS = {
    'user', 'input', 'request', 'req', 'query', 'param', 'body', 'form',
    'argv', 'environ', 'payload', 'cmd', 'command',
    'raw', 'unsafe', 'unvalidated', 'untrusted', 'external', 'remote',
    'user_input', 'user_data', 'raw_data', 'form_data', 'request_data',
}
# Pre-compiled regex for splitting identifiers into semantic segments  
# Splits on: underscores, dots, and camelCase boundaries
_SEGMENT_SPLITTER = _re.compile(r'[_.]|(?<=[a-z])(?=[A-Z])')

def _matches_hint(name: str) -> bool:
    """Check if a variable/path name matches an untrusted hint.
    
    Splits names into segments by '_', '.', and camelCase boundaries,
    then checks for exact segment matches against the hints set.
    
    Examples:
        'user_input'          → ['user', 'input']         → MATCH (both are hints)
        'metadata'            → ['metadata']               → NO MATCH
        'environment_config'  → ['environment', 'config']  → NO MATCH
        'os.environ'          → ['os', 'environ']          → MATCH ('environ')
        'requestCount'        → ['request', 'Count']       → MATCH ('request')
    """
    segments = _SEGMENT_SPLITTER.split(name)
    return any(seg.lower() in UNTRUSTED_VAR_HINTS for seg in segments if seg)

# Qualified sink definitions: maps method names to the caller objects that make them dangerous
# Format: 'method_name': { 'risk_type': str, 'dangerous_callers': Optional[set] }
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

# Global state for Inter-Procedural Propagation
# Maps function name to details about which arguments are tainted by entrypoints
# Format: { 'function_name': { 'tainted_indices': set() } }
GLOBAL_PROPAGATION_MAP = {}

@dataclass
class TaintFlow:
    sink_node: any # ast.AST or tree_sitter.Node
    tainted_vars: List[str]
    code_slice: List[str]
    sink_type: str
    lineno: int
    function_name: str = "global"
    vulnerable_syntax: str = ""
    confidence: str = "Low"

class ASTScanner(ast.NodeVisitor):
    def __init__(self, source_code: str, propagation_map: Optional[Dict] = None):
        self.source_lines = source_code.splitlines()
        self.tainted_vars = set()
        self.explicit_sources = set()  # High confidence tainted vars
        self.findings: List[TaintFlow] = []
        self.current_func = "global"
        self.scope_stack = []
        self.imported_modules = set()  # Track imports for scope awareness
        self.propagation_map = propagation_map or GLOBAL_PROPAGATION_MAP
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

    def visit_ClassDef(self, node: ast.ClassDef):
        """Track class scope for qualified function naming."""
        old_func = self.current_func
        self.scope_stack.append(node.name)
        self.current_func = f"{node.name} (class body)"
        
        self.generic_visit(node)
        
        self.scope_stack.pop()
        self.current_func = old_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Handle async functions identical to standard functions."""
        self.visit_FunctionDef(node)

    def visit_FunctionDef(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]):
        """Analyze each function independently (Intra-function)."""
        old_func = self.current_func
        qualified_name = ".".join(self.scope_stack + [node.name])
        self.current_func = qualified_name
        
        # Clear/Track taint for a new function scope
        old_taint = self.tainted_vars.copy()
        old_explicit = self.explicit_sources.copy()
        
        # Entry points: Function arguments are considered tainted. 
        # For World-Class precision, we mark them High Confidence if they match 
        # known framework-style 'untrusted' signatures.
        for i, arg in enumerate(node.args.args):
            self.tainted_vars.add(arg.arg)
            
            # [World-Class]: Check if this function was identified as a propagator in the Pre-Pass
            prop_info = self.propagation_map.get(node.name)
            is_global_propagator = prop_info and i in prop_info.get('tainted_indices', set())
            
            # Conventional handler signatures: request, req, payload, data
            if arg.arg.lower() in {'request', 'req', 'request_data', 'request_params', 'payload', 'user_input'} or is_global_propagator:
                self.explicit_sources.add(arg.arg)
        
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

    def _get_root_name(self, node) -> Optional[str]:
        """Resolves the root variable name for Name, Attribute, and Subscript nodes."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_root_name(node.value)
        elif isinstance(node, ast.Subscript):
            return self._get_root_name(node.value)
        return None

    def _get_full_path(self, node) -> Optional[str]:
        """Resolves full attribute path like os.environ.get"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_full_path(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return None

    def _is_untrusted_node(self, node) -> bool:
        """Checks if a node is an untrusted source based on path or word-boundary name hints."""
        path = self._get_full_path(node)
        if path:
            if path in UNTRUSTED_SOURCES: return True
            # Use word-boundary matching to avoid 'metadata' matching 'data', etc.
            if _matches_hint(path): return True
        
        if isinstance(node, ast.Call):
            return self._is_untrusted_node(node.func)
        return False

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Handle annotated assignments: val: str = untrusted"""
        if node.value:
            self._process_assignment([node.target], node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """Handle augmented assignments: query += untrusted"""
        # In augmented assignment, the target is ALSO an input to the RHS operation
        self._process_assignment([node.target], node.value, is_augmented=True)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Track data flow through assignments with Flow-Sensitive logic."""
        self._process_assignment(node.targets, node.value)
        self.generic_visit(node)

    def _process_assignment(self, targets: List[ast.AST], value: ast.AST, is_augmented: bool = False):
        """Core logic for taint propagation and flow-sensitive removal."""
        # 1. Sanitizer Check (Breaks the chain)
        if isinstance(value, ast.Call) and self._is_sanitizer_call(value):
            for target in targets:
                root = self._get_root_name(target)
                if root:
                    self.tainted_vars.discard(root)
                    self.explicit_sources.discard(root)
            return

        is_rh_tainted = False
        is_explicit_source = False
        
        # 2. Extract Taint from RHS
        for sub_node in ast.walk(value):
            if self._is_untrusted_node(sub_node):
                is_rh_tainted = True
                is_explicit_source = True
                break
            
            # Check for existing taint propagation
            root = self._get_root_name(sub_node)
            if root and root in self.tainted_vars:
                is_rh_tainted = True
                if root in self.explicit_sources:
                    is_explicit_source = True

        # 3. Apply/Remove Taint on LHS
        for target in targets:
            root = self._get_root_name(target)
            if not root: continue

            if is_rh_tainted:
                self.tainted_vars.add(root)
                if is_explicit_source:
                    self.explicit_sources.add(root)
            elif not is_augmented:
                # [Flow-Sensitive]: If not an augmented assignment and RHS is safe, 
                # the target is now clean (Literal Overwrite).
                self.tainted_vars.discard(root)
                self.explicit_sources.discard(root)

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
                            # [Fix Point 3]: "Safe List Execution" Logic Hardening
                            # Rule: subprocess.run(["command", tainted_arg]) is SAFE.
                            # Rule: subprocess.run([tainted_cmd, "--arg"]) is DANGEROUS.
                            # We must verify the first element is a static string constant.
                            safe_cmd = False
                            if isinstance(node.args[0], ast.List) and node.args[0].elts:
                                first_item = node.args[0].elts[0]
                                if isinstance(first_item, ast.Constant) and isinstance(first_item.value, str):
                                    # It's a static literal command, e.g., ["git", ...]
                                    safe_cmd = True
                            
                            if safe_cmd:
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

def analyze_python_taint(file_path: str, code: str, propagation_map: Optional[Dict] = None) -> List[TaintFlow]:
    """Analyze a single Python file using AST for vulnerability patterns."""
    try:
        scanner = ASTScanner(code, propagation_map)
        tree = ast.parse(code)
        scanner.visit(tree)
        return scanner.findings
    except (SyntaxError, ValueError):
        return []

class CallGraphScanner(ast.NodeVisitor):
    """Pass 1 Scanner: Records function calls that receive tainted data.
    
    This is used to build the Inter-Procedural Propagation Map.
    Uses flow-sensitive logic (matching the main ASTScanner) to avoid
    over-approximating taint when variables are overwritten with safe values.
    """
    def __init__(self, source_code: str):
        self.tainted_vars = set()
        self.current_func = "global"
        self.scope_stack = []
        self.propagation_map = {}
        # Seed with initial sources
        for src in UNTRUSTED_SOURCES:
            self.tainted_vars.add(src)

    def _get_root_name(self, node) -> Optional[str]:
        """Resolves the root variable name for Name, Attribute, and Subscript nodes."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_root_name(node.value)
        elif isinstance(node, ast.Subscript):
            return self._get_root_name(node.value)
        return None

    def _get_full_path(self, node) -> Optional[str]:
        """Resolves full attribute path like os.environ.get"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_full_path(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return None

    def _is_rhs_tainted(self, value_node) -> bool:
        """Check if a RHS expression contains tainted data."""
        for sub_node in ast.walk(value_node):
            # Check full attribute paths against UNTRUSTED_SOURCES
            path = self._get_full_path(sub_node)
            if path and (path in UNTRUSTED_SOURCES or _matches_hint(path)):
                return True
            # Check if it's a call to an untrusted source
            if isinstance(sub_node, ast.Call):
                func_path = self._get_full_path(sub_node.func)
                if func_path and (func_path in UNTRUSTED_SOURCES or _matches_hint(func_path)):
                    return True
            # Check existing taint propagation
            root = self._get_root_name(sub_node)
            if root and root in self.tainted_vars:
                return True
        return False

    def _is_safe_literal(self, node) -> bool:
        """Check if a node is a safe literal (string, number, bool, None, list/dict of literals)."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self._is_safe_literal(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return all(self._is_safe_literal(v) for v in node.values if v)
        return False

    def visit_Assign(self, node: ast.Assign):
        """Flow-sensitive assignment tracking for the pre-pass."""
        # Check if RHS is a sanitizer call — breaks the taint chain
        if isinstance(node.value, ast.Call):
            func_name = ""
            if isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                func_name = node.value.func.attr
            if func_name.lower() in SANITIZER_FUNCTIONS:
                for target in node.targets:
                    root = self._get_root_name(target)
                    if root:
                        self.tainted_vars.discard(root)
                self.generic_visit(node)
                return

        is_tainted = self._is_rhs_tainted(node.value)

        for target in node.targets:
            root = self._get_root_name(target)
            if not root:
                continue
            if is_tainted:
                self.tainted_vars.add(root)
            elif self._is_safe_literal(node.value):
                # [Flow-Sensitive]: Literal overwrite removes taint
                self.tainted_vars.discard(root)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        """Handle augmented assignments: query += untrusted"""
        if self._is_rhs_tainted(node.value):
            root = self._get_root_name(node.target)
            if root:
                self.tainted_vars.add(root)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        """Track class scope for qualified names in pre-pass."""
        old_func = self.current_func
        self.scope_stack.append(node.name)
        self.current_func = f"{node.name} (class body)"
        self.generic_visit(node)
        self.scope_stack.pop()
        self.current_func = old_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Handle async functions in pre-pass."""
        self.visit_FunctionDef(node)

    def visit_FunctionDef(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]):
        """Track custom function calls passing tainted data."""
        old_func = self.current_func
        qualified_name = ".".join(self.scope_stack + [node.name])
        self.current_func = qualified_name
        self.scope_stack.append(node.name)
        
        self.generic_visit(node)
        
        self.scope_stack.pop()
        self.current_func = old_func

    def visit_Call(self, node: ast.Call):
        """Check if this is a custom function call passing tainted data."""
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if func_name and func_name not in SCOPED_SINKS and func_name not in SANITIZER_FUNCTIONS:
            # Check arguments
            for i, arg in enumerate(node.args):
                for sub_node in ast.walk(arg):
                    root = self._get_root_name(sub_node)
                    if root and root in self.tainted_vars:
                        if func_name not in self.propagation_map:
                            self.propagation_map[func_name] = {'tainted_indices': set()}
                        self.propagation_map[func_name]['tainted_indices'].add(i)
                        break  # One tainted reference per arg is enough
        
        self.generic_visit(node)

def run_taint_pre_pass_single(file_path: str) -> Dict:
    """Pass 1 for a single file. Returns a local propagation map."""
    local_map = {}
    if file_path.endswith('.py'):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            tree = ast.parse(code)
            # We pass a local_map to the scanner
            scanner = CallGraphScanner(code)
            scanner.propagation_map = local_map
            scanner.visit(tree)
        except:
            pass
    return local_map

def merge_propagation_maps(maps: List[Dict]) -> Dict:
    """Combines multiple propagation maps into one."""
    merged = {}
    for m in maps:
        for func_name, info in m.items():
            if func_name not in merged:
                merged[func_name] = {'tainted_indices': set()}
            merged[func_name]['tainted_indices'].update(info['tainted_indices'])
    return merged

class TreeSitterScanner:
    """Universal scanner for JS/TS using Tree-Sitter."""
    def __init__(self, language: str, source_code: str):
        self.language = language
        self.source_lines = source_code.splitlines()
        self.source_bytes = source_code.encode('utf-8')
        
        # Lazy import to avoid top-level dependency crash
        try:
            from tree_sitter_languages import get_parser
            self.parser = get_parser(language)
        except ImportError:
            self.parser = None
            
        self.tainted_vars = set()
        self.explicit_sources = set()
        self.findings: List[TaintFlow] = []
        self.current_func = "global"
        self.scope_stack = []
        
        # Language-specific definitions
        self.language_config = {
            'javascript': {
                'sinks': ['exec', 'execSync', 'spawn', 'spawnSync', 'query', 'execute', 'raw', 'create', 'run', 'invoke', 'predict', 'upsert', 'eval', 'Function'],
                'funcs': ('function_declaration', 'arrow_function', 'method_definition'),
                'classes': ('class_declaration', 'class'),
                'assigns': ('assignment_expression', 'variable_declarator')
            },
            'typescript': {
                'sinks': ['exec', 'execSync', 'spawn', 'spawnSync', 'query', 'execute', 'raw', 'create', 'run', 'invoke', 'predict', 'upsert', 'eval', 'Function'],
                'funcs': ('function_declaration', 'arrow_function', 'method_definition'),
                'classes': ('class_declaration', 'class'),
                'assigns': ('assignment_expression', 'variable_declarator')
            },
            'java': {
                'sinks': ['exec', 'start', 'execute', 'executeQuery', 'executeUpdate', 'createNativeQuery', 'create', 'run'],
                'funcs': ('method_declaration', 'constructor_declaration'),
                'classes': ('class_declaration', 'interface_declaration', 'enum_declaration'),
                'assigns': ('assignment_expression', 'variable_declarator')
            },
            'go': {
                'sinks': ['Command', 'Query', 'Exec', 'QueryRow', 'Get', 'Post'],
                'funcs': ('function_declaration', 'method_declaration'),
                'classes': ('type_declaration',),
                'assigns': ('assignment_statement', 'short_var_declaration')
            }
        }
        
        config = self.language_config.get(language, self.language_config['javascript'])
        self.sink_list = config['sinks']
        self.func_types = config['funcs']
        self.class_types = config.get('classes', ())
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

    def _get_ts_root_name(self, node) -> Optional[str]:
        """Resolves the root identifier for complex Tree-Sitter nodes (member/subscript access)."""
        if node.type == 'identifier':
            return node.text.decode('utf-8')
        
        # JS/TS: member_expression, subscript_expression
        # Java: field_access, array_access
        # Go: selector_expression, index_expression
        if node.type in ('member_expression', 'subscript_expression', 'field_access', 'array_access', 'selector_expression', 'index_expression'):
            obj = node.child_by_field_name('object') or node.child_by_field_name('operand') or node.child_by_field_name('value')
            if obj:
                return self._get_ts_root_name(obj)
        return None

    def trace_node(self, node):
        """Recursively traverse Tree-Sitter nodes to find taint and sinks."""
        
        # 1. Detect Entry Points, Scope Boundaries & Update Function Context
        if node.type in self.class_types:
            name_node = node.child_by_field_name('name') or node.child_by_field_name('identifier')
            old_func = self.current_func
            class_name = "UnknownClass"
            if name_node:
                class_name = name_node.text.decode('utf-8')
            
            self.scope_stack.append(class_name)
            self.current_func = f"{class_name} (class body)"
            
            for child in node.children:
                self.trace_node(child)
            
            self.scope_stack.pop()
            self.current_func = old_func
            return

        if node.type in self.func_types:
            # Capture Name
            name_node = node.child_by_field_name('name') or node.child_by_field_name('identifier')
            old_func = self.current_func
            old_tainted = self.tainted_vars.copy()
            old_explicit = self.explicit_sources.copy()
            
            if name_node:
                func_name = name_node.text.decode('utf-8')
                self.current_func = ".".join(self.scope_stack + [func_name])

            params = node.child_by_field_name('parameters') or node.child_by_field_name('parameter_list')
            if params:
                stack = [params]
                while stack:
                    curr = stack.pop()
                    if curr.type == 'identifier':
                        var_name = curr.text.decode('utf-8')
                        self.tainted_vars.add(var_name)
                        # Heuristic: if param name hints at untrusted input, mark as explicit source
                        if _matches_hint(var_name):
                            self.explicit_sources.add(var_name)
                    stack.extend(curr.children)
            
            # Recurse and then restore
            for child in node.children:
                self.trace_node(child)
            
            self.current_func = old_func
            self.tainted_vars = old_tainted
            self.explicit_sources = old_explicit
            return

        # 2. Detect Taint Propagation (Assignments)
        if node.type in self.assign_types:
            left = node.child_by_field_name('left') or node.child_by_field_name('name')
            right = node.child_by_field_name('right') or node.child_by_field_name('value')
            
            if not left and node.type in ('assignment_statement', 'short_var_declaration'):
                children = node.children
                if len(children) >= 3:
                    left = children[0]
                    right = children[2]
            
            if left and right:
                is_tainted = False
                is_explicit = False
                is_sanitizer = False
                
                # Check RHS identifiers for explicit untrusted sources
                # Walk the actual AST nodes instead of raw text substring matching
                # to avoid false positives from names like 'metadata', 'requestCount'
                rhs_ids = []
                id_stack = [right]
                while id_stack:
                    id_node = id_stack.pop()
                    if id_node.type == 'identifier':
                        rhs_ids.append(id_node.text.decode('utf-8'))
                    elif id_node.type in ('member_expression', 'field_access', 'selector_expression'):
                        # Build dotted path: req.body, process.env
                        full_text = id_node.text.decode('utf-8')
                        if full_text in UNTRUSTED_SOURCES:
                            is_tainted = True
                            is_explicit = True
                    id_stack.extend(id_node.children)
                
                if not is_tainted:
                    for rid in rhs_ids:
                        if rid in UNTRUSTED_SOURCES:
                            is_tainted = True
                            is_explicit = True
                            break
                        if _matches_hint(rid):
                            is_tainted = True
                            is_explicit = True
                            break

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
                
                # 3. Apply/Remove Taint
                root_var = self._get_ts_root_name(left)
                if root_var:
                    if is_sanitizer:
                        self.tainted_vars.discard(root_var)
                        self.explicit_sources.discard(root_var)
                    else:
                        # Check if any part of RHS is tainted
                        stack = [right]
                        while stack:
                            curr = stack.pop()
                            if curr.type == 'identifier':
                                name = curr.text.decode('utf-8')
                                if name in self.tainted_vars:
                                    is_tainted = True
                                    if name in self.explicit_sources:
                                        is_explicit = True
                            if curr.type == 'call_expression':
                                fn = curr.child_by_field_name('function')
                                if fn and b'Sprintf' in fn.text:
                                    is_tainted = True
                            stack.extend(curr.children)
                        
                        if is_tainted:
                            self.tainted_vars.add(root_var)
                            if is_explicit:
                                self.explicit_sources.add(root_var)
                        elif not node.type == 'augmented_assignment': # Basic check for augmented in TS
                            # [Flow-Sensitive Discard]: RHS is safe, variable is now clean
                            self.tainted_vars.discard(root_var)
                            self.explicit_sources.discard(root_var)

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
                            # OR if the variable was marked as an explicit source (e.g. process.env)
                            is_high_conf = any(v in self.explicit_sources for v in tainted_found) or any(
                                _matches_hint(vname)
                                for vname in tainted_found
                            )
                            confidence = "High" if is_high_conf else "Low"

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
        if not scanner.parser:
            return []
        tree = scanner.parser.parse(code.encode('utf-8'))
        scanner.trace_node(tree.root_node)
        return scanner.findings
    except Exception as e:
        return []

# Legacy export for scanner.py compatibility
def analyze_js_taint(file_path: str, code: str) -> List[TaintFlow]:
    return analyze_enterprise_taint(file_path, code)
