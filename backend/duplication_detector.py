"""
duplication_detector.py — Finds near-duplicate ("clone") code blocks across
the project: the same logic copy-pasted into multiple files (or multiple
places in one file) instead of being extracted into a shared function.

Approach (a simplified, from-scratch version of what tools like PMD's CPD
do): normalize each line, hash a sliding window of consecutive lines, and
group files/positions that hash identically. Consecutive matching windows
between the same two locations are merged into one longer span instead of
being reported as many overlapping small chunks.

This is line/token-based, not AST-based — it won't catch renamed-variable
clones the way a real clone-detection tool does, but it needs no extra
dependency and runs in well under a second on typical project sizes.
"""

import re
import hashlib
from dataclasses import dataclass, field

from .ingestion import ProjectMap

WINDOW_SIZE = 6          # consecutive normalized lines that must match to count as a candidate
MIN_LINE_LEN = 4          # lines shorter than this after stripping are ignored (braces, blank, etc.)
MAX_GROUPS_RETURNED = 40  # keep the report readable on large repos

CODE_LANGUAGES = {
    "Python", "JavaScript", "TypeScript", "Java", "PHP", "Ruby", "Go", "C#", "C", "C++",
}

_WS_RE = re.compile(r"\s+")


@dataclass
class DuplicateGroup:
    file_a: str
    start_line_a: int
    end_line_a: int
    file_b: str
    start_line_b: int
    end_line_b: int
    line_count: int
    preview: str = field(default="")


def _normalize_line(line: str) -> str:
    return _WS_RE.sub(" ", line.strip())


def _tokenize_file(abs_path: str) -> list[tuple[int, str]]:
    """Returns [(original_line_number, normalized_text), ...] excluding blank/trivial lines."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            raw_lines = f.readlines()
    except OSError:
        return []
    tokens = []
    for i, line in enumerate(raw_lines, start=1):
        norm = _normalize_line(line)
        if len(norm) >= MIN_LINE_LEN:
            tokens.append((i, norm))
    return tokens


def _window_hash(tokens: list[tuple[int, str]], start: int) -> str:
    text = "\n".join(t[1] for t in tokens[start:start + WINDOW_SIZE])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def find_duplicates(pm: ProjectMap, window_size: int = WINDOW_SIZE) -> list[DuplicateGroup]:
    files_tokens = {}
    for pf in pm.files:
        if pf.language not in CODE_LANGUAGES:
            continue
        tokens = _tokenize_file(pf.abs_path)
        if len(tokens) >= window_size:
            files_tokens[pf.path] = tokens

    # hash -> list of (file, window_start_index)
    buckets: dict[str, list[tuple[str, int]]] = {}
    for path, tokens in files_tokens.items():
        for i in range(len(tokens) - window_size + 1):
            h = _window_hash(tokens, i)
            buckets.setdefault(h, []).append((path, i))

    # Build edges against a canonical (first-seen) occurrence per bucket, skipping
    # trivial same-file/overlapping-window matches.
    edges = []  # (file_a, i_a, file_b, i_b)
    for entries in buckets.values():
        if len(entries) < 2:
            continue
        canonical_file, canonical_i = entries[0]
        for other_file, other_i in entries[1:]:
            if canonical_file == other_file and abs(canonical_i - other_i) < window_size:
                continue
            edges.append((canonical_file, canonical_i, other_file, other_i))

    # Group edges by (file_a, file_b, offset) so consecutive window starts merge
    # into one contiguous duplicate span instead of many overlapping small ones.
    groups: dict[tuple, list[int]] = {}
    for file_a, i_a, file_b, i_b in edges:
        key = (file_a, file_b, i_b - i_a)
        groups.setdefault(key, []).append(i_a)

    duplicate_groups: list[DuplicateGroup] = []
    for (file_a, file_b, offset), starts in groups.items():
        starts = sorted(set(starts))
        run_start = starts[0]
        prev = starts[0]
        for s in starts[1:] + [None]:
            if s is not None and s == prev + 1:
                prev = s
                continue
            # close out the current run [run_start .. prev]
            run_len_windows = prev - run_start + 1
            total_lines = run_len_windows + window_size - 1
            tokens_a = files_tokens[file_a]
            tokens_b = files_tokens[file_b]
            start_line_a = tokens_a[run_start][0]
            end_line_a = tokens_a[min(run_start + total_lines - 1, len(tokens_a) - 1)][0]
            start_line_b = tokens_b[run_start + offset][0]
            end_line_b = tokens_b[min(run_start + offset + total_lines - 1, len(tokens_b) - 1)][0]
            preview_lines = [t[1] for t in tokens_a[run_start:run_start + min(total_lines, 3)]]
            duplicate_groups.append(DuplicateGroup(
                file_a=file_a, start_line_a=start_line_a, end_line_a=end_line_a,
                file_b=file_b, start_line_b=start_line_b, end_line_b=end_line_b,
                line_count=total_lines, preview=" / ".join(preview_lines)[:200],
            ))
            if s is not None:
                run_start = s
                prev = s

    duplicate_groups.sort(key=lambda g: g.line_count, reverse=True)
    return duplicate_groups[:MAX_GROUPS_RETURNED]


def duplicates_to_dicts(groups: list[DuplicateGroup]) -> list[dict]:
    return [
        {
            "file_a": g.file_a, "lines_a": f"{g.start_line_a}-{g.end_line_a}",
            "file_b": g.file_b, "lines_b": f"{g.start_line_b}-{g.end_line_b}",
            "line_count": g.line_count, "preview": g.preview,
        }
        for g in groups
    ]
