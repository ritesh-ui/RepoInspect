import os
import ast
import json
import hashlib
import logging
from typing import List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

def _compute_repo_fingerprint(base_path: str, files: List[str]) -> str:
    """
    Computes a fingerprint for the repo based on file paths and their modification times.
    This allows us to detect if files have changed since last index, enabling cache invalidation.
    """
    hasher = hashlib.md5()
    # Sort for determinism
    for f in sorted(files):
        try:
            mtime = str(os.path.getmtime(f))
            hasher.update(f.encode())
            hasher.update(mtime.encode())
        except OSError:
            pass
    return hasher.hexdigest()

def _safe_collection_name(base_path: str) -> str:
    """
    Derives a UNIQUE, scoped ChromaDB collection name from the repo path.
    This guarantees zero cross-package collisions: each repo path gets
    its own collection, even if two different packages have the same file names.
    
    ChromaDB collection names must match: ^[a-zA-Z0-9][a-zA-Z0-9._-]{1,60}[a-zA-Z0-9]$
    We use a short md5 prefix of the absolute path to ensure uniqueness.
    """
    abs_path = os.path.abspath(base_path)
    path_hash = hashlib.md5(abs_path.encode()).hexdigest()[:16]
    return f"repo_{path_hash}"

class SemanticChunker:
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.chunks = []

    def extract_chunks(self):
        if self.file_path.endswith('.py'):
            self._chunk_python()
        else:
            self._chunk_generic()
        return self.chunks

    def _chunk_python(self):
        try:
            tree = ast.parse(self.source_code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start_lineno = node.lineno
                    end_lineno = getattr(node, 'end_lineno', node.lineno + 10)
                    code_snippet = ast.get_source_segment(self.source_code, node)
                    if code_snippet:
                        self.chunks.append({
                            "id": f"{self.file_path}:{node.name}:{start_lineno}",
                            "text": f"File: {self.file_path}\nLine {start_lineno}-{end_lineno}\nType: {type(node).__name__}\nName: {node.name}\n\n{code_snippet}",
                            "metadata": {
                                "file": self.file_path,
                                "name": node.name,
                                "start_line": start_lineno,
                                "end_line": end_lineno
                            }
                        })
        except SyntaxError:
            self._chunk_generic()

    def _chunk_generic(self):
        # Fallback to ~50-line chunks for non-Python files
        chunk_size = 50
        for i in range(0, len(self.source_lines), chunk_size):
            end_idx = min(i + chunk_size, len(self.source_lines))
            snippet = "\n".join(self.source_lines[i:end_idx])
            self.chunks.append({
                "id": f"{self.file_path}:chunk_{i}",
                "text": f"File: {self.file_path}\nLine {i+1}-{end_idx}\n\n{snippet}",
                "metadata": {
                    "file": self.file_path,
                    "name": f"chunk_{i}",
                    "start_line": i + 1,
                    "end_line": end_idx
                }
            })

class RAGIndexer:
    def __init__(self, base_path: str):
        self.base_path = base_path
        # The DB is stored globally (not inside each repo), keyed by a repo fingerprint
        # This avoids polluting target repositories with .repoinspect folders
        self.db_dir = os.path.join(os.path.expanduser("~"), ".repoinspect", "chroma_db")
        os.makedirs(self.db_dir, exist_ok=True)
        
        # Each repo gets its own uniquely-named collection — zero cross-package collision
        self._collection_name = _safe_collection_name(base_path)
        self._fingerprint_file = os.path.join(self.db_dir, f"{self._collection_name}.fingerprint")
        
        try:
            import chromadb
            from chromadb.utils import embedding_functions
            self.client = chromadb.PersistentClient(path=self.db_dir)
            
            # Local Provider Support for Embeddings
            local_provider = os.environ.get("REPOINSPECT_LOCAL_PROVIDER")
            if local_provider == "ollama":
                ef = embedding_functions.OpenAIEmbeddingFunction(
                    api_key="ollama",
                    api_base="http://localhost:11434/v1",
                    model_name=os.environ.get("LOCAL_MODEL", "llama3")
                )
            elif local_provider == "lmstudio":
                ef = embedding_functions.OpenAIEmbeddingFunction(
                    api_key="lmstudio",
                    api_base="http://localhost:1234/v1",
                    model_name=os.environ.get("LOCAL_MODEL", "local-model")
                )
            else:
                ef = embedding_functions.OpenAIEmbeddingFunction(
                    api_key=os.getenv("OPENAI_API_KEY"),
                    model_name="text-embedding-3-small"
                )

            self.collection = self.client.get_or_create_collection(
                name=self._collection_name,
                embedding_function=ef
            )
            self.enabled = True
        except ImportError:
            console.print("[yellow]Warning: chromadb not installed. GraphRAG disabled.[/yellow]")
            self.enabled = False
        except Exception as e:
            console.print(f"[red]Error initializing ChromaDB: {e}[/red]")
            self.enabled = False

    def _is_stale(self, current_fingerprint: str) -> bool:
        """Returns True if the index is missing or the repo files have changed since last index."""
        if not os.path.exists(self._fingerprint_file):
            return True
        with open(self._fingerprint_file, 'r') as f:
            cached_fingerprint = f.read().strip()
        return cached_fingerprint != current_fingerprint

    def _save_fingerprint(self, fingerprint: str):
        """Persists the current fingerprint to disk for future stale checks."""
        with open(self._fingerprint_file, 'w') as f:
            f.write(fingerprint)

    def index_files(self, files: List[str]):
        if not self.enabled:
            return

        current_fingerprint = _compute_repo_fingerprint(self.base_path, files)

        if not self._is_stale(current_fingerprint):
            # Cache hit: files haven't changed since last index
            console.print(
                f"[bold green]✅ AST-Aware GraphRAG: Loaded cached index "
                f"({self.collection.count()} semantic blocks). "
                f"Files unchanged since last scan.[/bold green]"
            )
            return

        # Cache miss or stale: wipe old data and re-index from scratch
        if self.collection.count() > 0:
            console.print("[yellow]🔄 Source files changed — rebuilding GraphRAG index...[/yellow]")
            self.client.delete_collection(self._collection_name)
            
            from chromadb.utils import embedding_functions
            local_provider = os.environ.get("REPOINSPECT_LOCAL_PROVIDER")
            if local_provider == "ollama":
                ef = embedding_functions.OpenAIEmbeddingFunction(
                    api_key="ollama",
                    api_base="http://localhost:11434/v1",
                    model_name=os.environ.get("LOCAL_MODEL", "llama3")
                )
            elif local_provider == "lmstudio":
                ef = embedding_functions.OpenAIEmbeddingFunction(
                    api_key="lmstudio",
                    api_base="http://localhost:1234/v1",
                    model_name=os.environ.get("LOCAL_MODEL", "local-model")
                )
            else:
                ef = embedding_functions.OpenAIEmbeddingFunction(
                    api_key=os.getenv("OPENAI_API_KEY"),
                    model_name="text-embedding-3-small"
                )
                
            self.collection = self.client.get_or_create_collection(
                name=self._collection_name,
                embedding_function=ef
            )

        console.print(f"[bold yellow]⏳ Building AST-Aware GraphRAG Vector Index for {len(files)} files...[/bold yellow]")

        all_chunks = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            chunk_task = progress.add_task("[green]Parsing and Chunking files...", total=len(files))
            for file_path in files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    rel_path = os.path.relpath(file_path, self.base_path)
                    chunker = SemanticChunker(rel_path, code)
                    all_chunks.extend(chunker.extract_chunks())
                except Exception:
                    pass
                progress.advance(chunk_task)

        if not all_chunks:
            console.print("[yellow]No semantic chunks found to index.[/yellow]")
            return

        ids = [c["id"] for c in all_chunks]
        documents = [c["text"] for c in all_chunks]
        metadatas = [c["metadata"] for c in all_chunks]

        batch_size = 100

        # Token-safe truncation using tiktoken
        try:
            import tiktoken
            encoding = tiktoken.get_encoding("cl100k_base")
        except ImportError:
            encoding = None

        def truncate_text(text: str, max_tokens: int = 8000) -> str:
            if not encoding:
                return text[:max_tokens * 3]  # ~4 chars/token fallback
            tokens = encoding.encode(text)
            if len(tokens) > max_tokens:
                return encoding.decode(tokens[:max_tokens]) + "\n... [TRUNCATED]"
            return text

        safe_documents = [truncate_text(doc) for doc in documents]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Embedding Semantic Blocks...", total=len(ids))
            for i in range(0, len(ids), batch_size):
                end_idx = i + batch_size
                self.collection.upsert(
                    ids=ids[i:end_idx],
                    documents=safe_documents[i:end_idx],
                    metadatas=metadatas[i:end_idx]
                )
                progress.advance(task, advance=len(ids[i:end_idx]))

        # Persist fingerprint so next scan can use the cache
        self._save_fingerprint(current_fingerprint)
        console.print(f"[bold green]✅ AST-Aware GraphRAG: Successfully indexed {len(ids)} semantic blocks.[/bold green]")

    def semantic_search(self, query: str, n_results: int = 3) -> str:
        if not self.enabled:
            return "Error: GraphRAG disabled."
        if self.collection.count() == 0:
            return "Error: Vector database is empty."
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            if not results['documents'] or not results['documents'][0]:
                return "No semantic blocks found matching query."
            return "\n\n--- SEMANTIC SEARCH RESULTS ---\n\n".join(results['documents'][0])
        except Exception as e:
            return f"Error during semantic search: {e}"


_RAG_INDEXER = None

def init_rag_indexer(base_path: str, files: List[str]):
    global _RAG_INDEXER
    local_provider = os.environ.get("REPOINSPECT_LOCAL_PROVIDER")
    if not local_provider and not os.getenv("OPENAI_API_KEY"):
        console.print("[yellow]Skipping AST-Aware GraphRAG: No OPENAI_API_KEY found.[/yellow]")
        return
    try:
        _RAG_INDEXER = RAGIndexer(base_path)
        _RAG_INDEXER.index_files(files)
    except Exception as e:
        console.print(f"[red]Failed to initialize GraphRAG: {e}[/red]")

def query_rag(query: str) -> str:
    global _RAG_INDEXER
    if not _RAG_INDEXER:
        return "Error: AST-Aware GraphRAG is not initialized."
    return _RAG_INDEXER.semantic_search(query)
