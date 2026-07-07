"""
embeddings.py — Chunks the codebase (by function/class for Python via AST,
by sliding line-window for other languages) and embeds each chunk locally
on CPU using sentence-transformers (all-MiniLM-L6-v2, ~80MB, no GPU/API key
needed). Embeddings + chunk metadata are cached to disk per-scan so repeat
chat queries don't re-embed.

This is what powers "chat with the repo" with real file:line citations.
"""

import ast
import pickle
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .ingestion import ProjectMap

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
CACHE_DIR = Path(__file__).parent.parent / "data" / "embedding_cache"

CHUNKABLE_LANGS = {
    "Python", "JavaScript", "TypeScript", "Java", "Go", "Ruby", "PHP", "C", "C++", "C#", "Rust",
}
WINDOW_LINES = 40
WINDOW_OVERLAP = 8


@dataclass
class Chunk:
    file_path: str
    start_line: int
    end_line: int
    text: str
    symbol_name: str = ""  # function/class name if applicable


@dataclass
class EmbeddingIndex:
    chunks: list[Chunk] = field(default_factory=list)
    vectors: np.ndarray | None = None  # shape (n_chunks, dim), L2-normalized

    def search(self, query_vector: np.ndarray, top_k: int = 6) -> list[tuple[Chunk, float]]:
        if self.vectors is None or len(self.chunks) == 0:
            return []
        sims = self.vectors @ query_vector  # cosine similarity (vectors are normalized)
        top_idx = np.argsort(-sims)[:top_k]
        return [(self.chunks[i], float(sims[i])) for i in top_idx]


def _chunk_python_file(path: str, rel_path: str) -> list[Chunk]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        lines = source.splitlines()
        tree = ast.parse(source)
    except (SyntaxError, OSError):
        return _chunk_generic_file(path, rel_path)

    chunks = []
    top_level_symbol_nodes = [
        n for n in ast.iter_child_nodes(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    if not top_level_symbol_nodes:
        return _chunk_generic_file(path, rel_path)

    for node in top_level_symbol_nodes:
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        text = "\n".join(lines[start - 1:end])
        if text.strip():
            chunks.append(Chunk(rel_path, start, end, text, symbol_name=node.name))
    return chunks


def _chunk_generic_file(path: str, rel_path: str) -> list[Chunk]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    chunks = []
    step = WINDOW_LINES - WINDOW_OVERLAP
    for start in range(0, len(lines), step):
        end = min(start + WINDOW_LINES, len(lines))
        text = "".join(lines[start:end])
        if text.strip():
            chunks.append(Chunk(rel_path, start + 1, end, text))
        if end == len(lines):
            break
    return chunks


def chunk_project(pm: ProjectMap) -> list[Chunk]:
    all_chunks = []
    for pf in pm.files:
        if pf.language not in CHUNKABLE_LANGS:
            continue
        if pf.language == "Python":
            all_chunks.extend(_chunk_python_file(pf.abs_path, pf.path))
        else:
            all_chunks.extend(_chunk_generic_file(pf.abs_path, pf.path))
    return all_chunks


def _cache_key(pm: ProjectMap) -> str:
    """Hash based on file paths + sizes so identical re-uploads reuse the cache,
    but any content change invalidates it."""
    h = hashlib.sha256()
    for pf in sorted(pm.files, key=lambda f: f.path):
        h.update(f"{pf.path}:{pf.size_bytes}".encode())
    return h.hexdigest()[:16]


_MODEL_CACHE = {}


def _get_model():
    """Load the embedding model once per process (it's ~80MB; reloading per
    query would be slow). Imported lazily so the rest of the app works even
    before this larger dependency is installed."""
    if "model" not in _MODEL_CACHE:
        from sentence_transformers import SentenceTransformer
        _MODEL_CACHE["model"] = SentenceTransformer(EMBEDDING_MODEL_NAME, device="cpu")
    return _MODEL_CACHE["model"]


def build_or_load_index(pm: ProjectMap, force_rebuild: bool = False) -> EmbeddingIndex:
    """Builds (or loads a cached) local embedding index for the project."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{_cache_key(pm)}.pkl"

    if cache_file.exists() and not force_rebuild:
        with open(cache_file, "rb") as f:
            return pickle.load(f)

    chunks = chunk_project(pm)
    if not chunks:
        return EmbeddingIndex(chunks=[], vectors=np.zeros((0, 384)))

    model = _get_model()
    texts = [f"# {c.file_path}\n{c.text}" for c in chunks]
    vectors = model.encode(
        texts, batch_size=32, show_progress_bar=False, normalize_embeddings=True,
    )
    index = EmbeddingIndex(chunks=chunks, vectors=np.asarray(vectors, dtype=np.float32))

    with open(cache_file, "wb") as f:
        pickle.dump(index, f)
    return index


def embed_query(query: str) -> np.ndarray:
    model = _get_model()
    vec = model.encode([query], normalize_embeddings=True)[0]
    return np.asarray(vec, dtype=np.float32)
