import os

SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.yaml', '.txt'}
IGNORE_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'env', '.env', 'dist', 'build', 'docs'}

def get_repo_files(repo_path):
    """
    Recursively find all supported files in the repository.
    """
    found_files = []
    for root, dirs, files in os.walk(repo_path):
        # In-place modify dirs to skip ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                found_files.append(os.path.join(root, file))
    
    return found_files

def read_file_content(file_path):
    """
    Read file content safely handling encoding issues.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []
