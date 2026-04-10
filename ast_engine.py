import ast
from tree_sitter_languages import get_parser
from dataclasses import dataclass
from dataclasses import dataclass
from typing import List, Set, Dict, Optional

@dataclass
class TaintFlow:
    sink_node: any # ast.AST or tree_sitter.Node
    tainted_vars: List[str]
    code_slice: List[str]
    sink_type: str
    lineno: int
    function_name: str = "global"
    vulnerable_syntax: str = ""

class ASTScanner(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.source_lines = source_code.splitlines()
        self.tainted_vars = set()
        self.findings: List[TaintFlow] = []
        self.current_func = "global"
        
        # Define sinks (dangerous functions)
        self.sinks = {
            'Command Injection': [
                'system', 'run', 'Popen', 'call', 'check_output', 'check_call'
            ],
            'SQL Injection': [
                'execute', 'executemany'
            ],
            'AI Security Risk': [
                'create', 'run', 'upsert', 'query', 'invoke', 'predict'
            ],
            'Unsafe Eval': [
                'eval', 'exec'
            ]
        }

    def is_sink(self, node: ast.Call) -> Optional[str]:
        """Checks if a call node is a dangerous sink."""
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            
        for risk_type, funcs in self.sinks.items():
            if func_name in funcs:
                return risk_type
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
        
        # Entry points: Function arguments are considered tainted
        for arg in node.args.args:
            self.tainted_vars.add(arg.arg)
        
        # Visit children
        self.generic_visit(node)
        
        # Restore state
        self.tainted_vars = old_taint
        self.current_func = old_func

    def visit_Assign(self, node: ast.Assign):
        """Track data flow through assignments."""
        is_rh_tainted = False
        
        for sub_node in ast.walk(node.value):
            if isinstance(sub_node, ast.Name) and sub_node.id in self.tainted_vars:
                is_rh_tainted = True
                break
            if isinstance(sub_node, ast.Call) and isinstance(sub_node.func, ast.Name) and sub_node.func.id == 'input':
                is_rh_tainted = True
        
        if is_rh_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Detect when tainted data reaches a sink."""
        risk_type = self.is_sink(node)
        if risk_type:
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
                # Capture forensic syntax
                syntax = "Unknown"
                try:
                    syntax = self.source_lines[node.lineno-1].strip()
                except: pass

                self.findings.append(TaintFlow(
                    sink_node=node,
                    tainted_vars=list(set(tainted_args)),
                    code_slice=code_slice,
                    sink_type=risk_type,
                    lineno=node.lineno,
                    function_name=self.current_func,
                    vulnerable_syntax=syntax
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

    def is_sink(self, identifier: str) -> Optional[str]:
        categories = {
            'Command Injection': ['exec', 'execSync', 'spawn', 'spawnSync', 'start', 'Command'],
            'SQL Injection': ['query', 'execute', 'raw', 'executeQuery', 'executeUpdate', 'createNativeQuery', 'Query', 'Exec', 'QueryRow'],
            'AI Security Risk': ['create', 'run', 'invoke', 'predict', 'upsert'],
            'Unsafe Eval': ['eval', 'Function']
        }
        for cat, funcs in categories.items():
            if identifier in funcs:
                return cat
        return None

    def trace_node(self, node):
        """Recursively traverse Tree-Sitter nodes to find taint and sinks."""
        
        # 1. Detect Entry Points & Update Function Context
        if node.type in self.func_types:
            # Capture Name
            name_node = node.child_by_field_name('name')
            old_func = self.current_func
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
                if func_node.type in ('member_expression', 'field_access'):
                    prop = func_node.child_by_field_name('property') or func_node.child_by_field_name('name')
                    if prop: func_name = prop.text.decode('utf-8')
                else:
                    func_name = func_node.text.decode('utf-8')
                
                risk_type = self.is_sink(func_name)
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

                            self.findings.append(TaintFlow(
                                sink_node=node,
                                tainted_vars=list(set(tainted_found)),
                                code_slice=self.get_slice(node.start_point[0], node.end_point[0]),
                                sink_type=risk_type,
                                lineno=node.start_point[0] + 1,
                                function_name=self.current_func,
                                vulnerable_syntax=syntax
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
