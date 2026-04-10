import ast
from tree_sitter_languages import get_parser
from dataclasses import dataclass
from dataclasses import dataclass
from typing import List, Set, Dict, Optional

@dataclass
class TaintFlow:
    sink_node: ast.AST
    tainted_vars: List[str]
    code_slice: List[str]
    sink_type: str
    lineno: int

class ASTScanner(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.source_lines = source_code.splitlines()
        self.tainted_vars = set()
        self.findings: List[TaintFlow] = []
        
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
        # Clear taint for a new function scope
        old_taint = self.tainted_vars.copy()
        
        # Entry points: Function arguments are considered tainted
        for arg in node.args.args:
            self.tainted_vars.add(arg.arg)
        
        # Visit children
        self.generic_visit(node)
        
        # Restore taint (though we stay in function scope for this upgrade)
        self.tainted_vars = old_taint

    def visit_Assign(self, node: ast.Assign):
        """Track data flow through assignments."""
        # Simple taint tracking: if RHS is tainted or contains tainted var, LHS becomes tainted
        is_rh_tainted = False
        
        # Check if RHS has any tainted variables
        for sub_node in ast.walk(node.value):
            if isinstance(sub_node, ast.Name) and sub_node.id in self.tainted_vars:
                is_rh_tainted = True
                break
            # input() is a source
            if isinstance(sub_node, ast.Call) and isinstance(sub_node.func, ast.Name) and sub_node.func.id == 'input':
                is_rh_tainted = True
        
        # Propagate taint to targets
        if is_rh_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Detect when tainted data reaches a sink."""
        risk_type = self.is_sink(node)
        if risk_type:
            # Check if any argument is tainted
            tainted_args = []
            for arg in node.args:
                for sub_node in ast.walk(arg):
                    if isinstance(sub_node, ast.Name) and sub_node.id in self.tainted_vars:
                        tainted_args.append(sub_node.id)
            
            # Also check keywords
            for kw in node.keywords:
                for sub_node in ast.walk(kw.value):
                    if isinstance(sub_node, ast.Name) and sub_node.id in self.tainted_vars:
                        tainted_args.append(sub_node.id)

            if tainted_args:
                # Capture the finding
                code_slice = self.get_slice(node.lineno-5, node.lineno)
                self.findings.append(TaintFlow(
                    sink_node=node,
                    tainted_vars=list(set(tainted_args)),
                    code_slice=code_slice,
                    sink_type=risk_type,
                    lineno=node.lineno
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
        
        # Define sinks for JS/TS
        self.sinks = {
            'Command Injection': ['exec', 'execSync', 'spawn', 'spawnSync'],
            'SQL Injection': ['query', 'execute', 'raw'],
            'AI Security Risk': ['create', 'run', 'invoke', 'predict', 'upsert'],
            'Unsafe Eval': ['eval', 'Function']
        }

    def get_slice(self, start_row: int, end_row: int) -> List[str]:
        """Extracts lines of code from source."""
        return self.source_lines[max(0, start_row-5):end_row+2]

    def is_sink(self, identifier: str) -> Optional[str]:
        for risk_type, funcs in self.sinks.items():
            if identifier in funcs:
                return risk_type
        return None

    def trace_node(self, node):
        """Recursively traverse Tree-Sitter nodes to find taint and sinks."""
        
        # 1. Detect Entry Points (Function Parameters)
        if node.type in ('function_declaration', 'arrow_function', 'method_definition'):
            params = node.child_by_field_name('parameters')
            if params:
                for param in params.children:
                    if param.type == 'identifier':
                        self.tainted_vars.add(param.text.decode('utf-8'))

        # 2. Detect Taint Propagation (Assignments)
        if node.type == 'assignment_expression' or node.type == 'variable_declarator':
            left = node.child_by_field_name('left') or node.child_by_field_name('name')
            right = node.child_by_field_name('right') or node.child_by_field_name('value')
            
            if left and right:
                is_tainted = False
                # Check if right side has tainted vars
                # Use recurse check for right side
                for child in right.children:
                    if child.type == 'identifier' and child.text.decode('utf-8') in self.tainted_vars:
                        is_tainted = True
                # Simple check for right itself if it's an identifier
                if right.type == 'identifier' and right.text.decode('utf-8') in self.tainted_vars:
                    is_tainted = True
                
                if is_tainted:
                    self.tainted_vars.add(left.text.decode('utf-8'))

        # 3. Detect Sinks
        if node.type == 'call_expression':
            func = node.child_by_field_name('function')
            if func:
                # Handle direct calls (eval()) and attribute calls (client.query())
                func_name = ""
                if func.type == 'identifier':
                    func_name = func.text.decode('utf-8')
                elif func.type == 'member_expression':
                    prop = func.child_by_field_name('property')
                    if prop:
                        func_name = prop.text.decode('utf-8')
                
                risk_type = self.is_sink(func_name)
                if risk_type:
                    # Check if any argument is tainted
                    args = node.child_by_field_name('arguments')
                    if args:
                        tainted_found = []
                        # Tree-sitter arguments nodes have identifier children or expressions
                        for arg in args.children:
                            # We can walk the arg subtree to find identifiers
                            stack = [arg]
                            while stack:
                                curr = stack.pop()
                                if curr.type == 'identifier' and curr.text.decode('utf-8') in self.tainted_vars:
                                    tainted_found.append(curr.text.decode('utf-8'))
                                stack.extend(curr.children)
                        
                        if tainted_found:
                            self.findings.append(TaintFlow(
                                sink_node=node,
                                tainted_vars=list(set(tainted_found)),
                                code_slice=self.get_slice(node.start_point[0], node.end_point[0]),
                                sink_type=risk_type,
                                lineno=node.start_point[0] + 1
                            ))

        # Recurse
        for child in node.children:
            self.trace_node(child)

def analyze_js_taint(file_path: str, code: str) -> List[TaintFlow]:
    """Helper to run the Tree-Sitter scanner on JS/TS/JSX/TSX files."""
    lang = 'javascript'
    if file_path.endswith(('.ts', '.tsx')):
        lang = 'typescript'
    
    try:
        scanner = TreeSitterScanner(lang, code)
        tree = scanner.parser.parse(code.encode('utf-8'))
        scanner.trace_node(tree.root_node)
        return scanner.findings
    except Exception as e:
        return []
