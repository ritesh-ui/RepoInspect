import os
import re
import json

def restrict_path(base_path: str, target_path: str) -> str:
    """Ensures the target path is within the safe base repository path."""
    target = os.path.abspath(os.path.join(base_path, target_path))
    if not target.startswith(os.path.abspath(base_path)):
        raise ValueError("Paths outside the repository are restricted.")
    return target

def read_file(filepath: str, base_path: str) -> str:
    """Reads the contents of a file within the repository."""
    try:
        safe_path = restrict_path(base_path, filepath)
        if not os.path.exists(safe_path):
            return f"Error: File '{filepath}' does not exist."
        with open(safe_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            
        # Add line numbers for context
        content = "".join([f"{i+1}: {line}" for i, line in enumerate(lines)])
        return content
    except Exception as e:
        return f"Error reading file: {e}"

def text_search(query: str, base_path: str) -> str:
    """Searches for a text string or regex pattern across all supported files in the repo."""
    try:
        results = []
        ext_filter = ('.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go')
        pattern = re.compile(query, re.IGNORECASE)
        
        for root, _, files in os.walk(base_path):
            if 'node_modules' in root or '.git' in root or 'venv' in root:
                continue
            for file in files:
                if file.endswith(ext_filter):
                    filepath = os.path.join(root, file)
                    rel_path = os.path.relpath(filepath, base_path)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            for i, line in enumerate(f):
                                if pattern.search(line):
                                    results.append(f"{rel_path}:{i+1}: {line.strip()}")
                    except: pass
        if not results:
            return f"No occurrences of '{query}' found."
        
        # Truncate if too large to save tokens
        if len(results) > 50:
            return "\n".join(results[:50]) + f"\n... (and {len(results)-50} more occurrences omitted)"
        return "\n".join(results)
    except Exception as e:
        return f"Error searching text: {e}"

def list_directory(directory_path: str, base_path: str) -> str:
    """Lists files and folders inside a given directory."""
    try:
        safe_path = restrict_path(base_path, directory_path)
        if not os.path.exists(safe_path) or not os.path.isdir(safe_path):
            return f"Error: Directory '{directory_path}' does not exist."
            
        items = os.listdir(safe_path)
        files = []
        dirs = []
        for item in items:
            if item in ('.git', 'node_modules', 'venv', '__pycache__'): continue
            item_path = os.path.join(safe_path, item)
            if os.path.isdir(item_path):
                dirs.append(f"{item}/")
            else:
                files.append(item)
                
        output = []
        if dirs: output.extend(sorted(dirs))
        if files: output.extend(sorted(files))
        return "\n".join(output) if output else "Directory is empty."
    except Exception as e:
        return f"Error listing directory: {e}"

# OpenAI API Tool Definitions
AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Reads the entire contents of a file within the repository. Used to inspect how a function or class is implemented.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "The relative path to the file (e.g., 'utils/helpers.py')"
                    }
                },
                "required": ["filepath"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "text_search",
            "description": "Searches for a text string or regex pattern across all Python, JS/TS, Java, and Go files in the repository. Useful for finding all usages of a variable or finding where a function is defined.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The string or regex pattern to search for (e.g., 'def sanitize_input' or 'escape_str')"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "Lists the files and folders inside a specific directory. Useful if you need to explore the project structure to find a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory_path": {
                        "type": "string",
                        "description": "The relative path to the directory (e.g., '.' for root, or 'src/utils/')"
                    }
                },
                "required": ["directory_path"]
            }
        }
    }
]

def execute_tool(tool_name: str, arguments: str, base_path: str) -> str:
    """Executes a tool call requested by the LLM."""
    try:
        args = json.loads(arguments)
    except json.JSONDecodeError:
        return "Error: Invalid JSON arguments provided."

    if tool_name == "read_file":
        return read_file(args.get("filepath", ""), base_path)
    elif tool_name == "text_search":
        return text_search(args.get("query", ""), base_path)
    elif tool_name == "list_directory":
        return list_directory(args.get("directory_path", ""), base_path)
    else:
        return f"Error: Unknown tool '{tool_name}'."
