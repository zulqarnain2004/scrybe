"""
ingestion.py — Normalizes any input source (ZIP upload, single file, or a
public GitHub URL) into a local directory on disk, and builds a project
file map (tree + language breakdown).
"""

import os
import re
import shutil
import zipfile
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field

EXCLUDED_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".pytest_cache", ".mypy_cache", "target", ".idea", ".vscode", "vendor",
    "coverage", ".next", ".nuxt",
}

LANGUAGE_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP",
    ".c": "C", ".h": "C", ".cpp": "C++", ".hpp": "C++", ".cs": "C#", ".rs": "Rust",
    ".swift": "Swift", ".kt": "Kotlin", ".scala": "Scala", ".sql": "SQL",
    ".sh": "Shell", ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
    ".html": "HTML", ".css": "CSS", ".md": "Markdown",
}

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # skip anything absurdly large (binaries, lockfiles)


@dataclass
class ProjectFile:
    path: str            # relative path from project root
    abs_path: str
    language: str
    loc: int
    size_bytes: int


@dataclass
class ProjectMap:
    root_dir: str
    project_name: str
    files: list[ProjectFile] = field(default_factory=list)
    language_breakdown: dict = field(default_factory=dict)
    total_loc: int = 0
    is_git_repo: bool = False


class IngestionError(Exception):
    pass


def ingest_zip(zip_path: str, workdir: str) -> str:
    extract_dir = os.path.join(workdir, "project")
    os.makedirs(extract_dir, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            _safe_extract(zf, extract_dir)
    except zipfile.BadZipFile:
        raise IngestionError("The uploaded file isn't a valid ZIP archive.")
    return _flatten_if_single_subdir(extract_dir)


def _safe_extract(zf: zipfile.ZipFile, extract_dir: str):
    """Extract a ZIP while rejecting any member whose resolved path would land
    outside extract_dir (a.k.a. Zip Slip: entries like '../../etc/passwd' or
    absolute paths). zipfile.extractall() does not guard against this itself."""
    extract_root = os.path.realpath(extract_dir)
    for member in zf.infolist():
        member_path = os.path.realpath(os.path.join(extract_dir, member.filename))
        if member_path != extract_root and not member_path.startswith(extract_root + os.sep):
            raise IngestionError(f"Refusing to extract unsafe archive entry: {member.filename}")
    zf.extractall(extract_dir)


def ingest_single_file(file_path: str, workdir: str, original_name: str) -> str:
    extract_dir = os.path.join(workdir, "project")
    os.makedirs(extract_dir, exist_ok=True)
    dest = os.path.join(extract_dir, original_name)
    shutil.copy(file_path, dest)
    return extract_dir


def ingest_github(url: str, workdir: str) -> str:
    if not re.match(r"^https://github\.com/[\w.-]+/[\w.-]+/?$", url.strip()):
        raise IngestionError("Only public https://github.com/<owner>/<repo> URLs are supported.")
    extract_dir = os.path.join(workdir, "project")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "200", url.strip(), extract_dir],
            check=True, capture_output=True, text=True, timeout=180,
        )
    except subprocess.CalledProcessError as e:
        raise IngestionError(f"git clone failed: {e.stderr.strip()[:300]}")
    except subprocess.TimeoutExpired:
        raise IngestionError("Cloning the repository timed out (repo may be too large).")
    return extract_dir


def _flatten_if_single_subdir(extract_dir: str) -> str:
    """If a ZIP contains one top-level folder (common GitHub export pattern), descend into it."""
    entries = [e for e in os.listdir(extract_dir) if not e.startswith("__MACOSX") and not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(extract_dir, entries[0])):
        return os.path.join(extract_dir, entries[0])
    return extract_dir


def build_project_map(root_dir: str, project_name: str) -> ProjectMap:
    pm = ProjectMap(root_dir=root_dir, project_name=project_name)
    pm.is_git_repo = os.path.isdir(os.path.join(root_dir, ".git"))

    lang_counts: dict[str, int] = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]
        for fname in filenames:
            abs_path = os.path.join(dirpath, fname)
            try:
                size = os.path.getsize(abs_path)
            except OSError:
                continue
            if size == 0 or size > MAX_FILE_SIZE_BYTES:
                continue
            ext = Path(fname).suffix.lower()
            language = LANGUAGE_BY_EXT.get(ext)
            if language is None:
                continue  # skip binaries / unrecognized types for the code map
            loc = _count_loc(abs_path)
            if loc == 0:
                continue
            rel_path = os.path.relpath(abs_path, root_dir)
            pm.files.append(ProjectFile(rel_path, abs_path, language, loc, size))
            lang_counts[language] = lang_counts.get(language, 0) + loc
            pm.total_loc += loc

    pm.language_breakdown = dict(sorted(lang_counts.items(), key=lambda kv: -kv[1]))
    return pm


def _count_loc(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def make_workdir() -> str:
    return tempfile.mkdtemp(prefix="codesage_")


def cleanup_workdir(workdir: str):
    shutil.rmtree(workdir, ignore_errors=True)
