"""
git_analysis.py — EXTRA FEATURE beyond the original CodeSage post.

If the ingested project is a git repo (or was cloned from GitHub), this
mines the commit history to find:
  - Churn hotspots: files that change most often (correlates strongly with
    defect density in research like Nagappan & Ball's work at Microsoft).
  - Bus factor: files touched by only one author — a knowledge-silo risk.
  - Recent activity: commits in the last 30 days, to separate "actively
    risky" from "historically messy but now stable" code.
"""

import os
import subprocess
import time
from dataclasses import dataclass, field

from .ingestion import ProjectMap


@dataclass
class ChurnEntry:
    file_path: str
    commit_count: int
    author_count: int
    authors: list = field(default_factory=list)
    last_modified_days_ago: int = -1
    bus_factor_risk: bool = False  # True if author_count == 1 and commit_count >= 3


@dataclass
class GitAnalysisResult:
    available: bool = False
    total_commits: int = 0
    contributors: list = field(default_factory=list)
    churn: list = field(default_factory=list)  # sorted, worst first
    reason_unavailable: str = ""


def _run_git(args: list[str], cwd: str, timeout=60) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip())
    return proc.stdout


def analyze_git_history(pm: ProjectMap) -> GitAnalysisResult:
    result = GitAnalysisResult()
    if not pm.is_git_repo:
        result.reason_unavailable = "Not a git repository (uploaded as ZIP/file, not cloned from GitHub)."
        return result

    try:
        log_output = _run_git(
            ["log", "--pretty=format:%H|%an|%at", "--name-only"], cwd=pm.root_dir,
        )
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        result.reason_unavailable = f"Could not read git history: {e}"
        return result

    file_stats: dict[str, dict] = {}
    commit_hashes = set()
    contributors: dict[str, int] = {}
    now = time.time()
    current_author, current_ts, current_hash = None, None, None

    for line in log_output.splitlines():
        if "|" in line and len(line.split("|")) == 3:
            current_hash, current_author, ts = line.split("|")
            current_ts = int(ts)
            commit_hashes.add(current_hash)
            contributors[current_author] = contributors.get(current_author, 0) + 1
        elif line.strip():
            fpath = line.strip()
            entry = file_stats.setdefault(fpath, {"commits": 0, "authors": set(), "last_ts": 0})
            entry["commits"] += 1
            entry["authors"].add(current_author)
            entry["last_ts"] = max(entry["last_ts"], current_ts or 0)

    result.total_commits = len(commit_hashes)
    result.contributors = sorted(contributors.items(), key=lambda kv: -kv[1])

    valid_paths = {pf.path.replace(os.sep, "/") for pf in pm.files}
    churn_list = []
    for fpath, stats in file_stats.items():
        if fpath not in valid_paths:
            continue
        days_ago = int((now - stats["last_ts"]) / 86400) if stats["last_ts"] else -1
        entry = ChurnEntry(
            file_path=fpath, commit_count=stats["commits"],
            author_count=len(stats["authors"]), authors=sorted(stats["authors"]),
            last_modified_days_ago=days_ago,
            bus_factor_risk=(len(stats["authors"]) == 1 and stats["commits"] >= 3),
        )
        churn_list.append(entry)

    result.churn = sorted(churn_list, key=lambda c: -c.commit_count)[:20]
    result.available = True
    return result
