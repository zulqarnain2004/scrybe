"""
semgrep_scanner.py — Multi-language SAST via Semgrep, using a bundled ruleset
(backend/semgrep_rules/rules.yaml) so scans run fully offline instead of
fetching from the Semgrep registry. Complements bandit (Python-only, deep AST
checks) with command-injection / unsafe-deserialization / XSS / weak-crypto
/ path-traversal checks across JS, TS, Java, PHP, Go, and Ruby.
"""

import os
import json
import subprocess

from .ingestion import ProjectMap
from .security_scanner import Finding

RULES_PATH = os.path.join(os.path.dirname(__file__), "semgrep_rules", "rules.yaml")

SEMGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _read_snippet(abs_path: str, start_line: int, end_line: int) -> str:
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        # semgrep line numbers are 1-indexed and inclusive
        chunk = lines[max(0, start_line - 1):end_line]
        return " ".join(l.strip() for l in chunk).strip()[:160]
    except (OSError, IndexError):
        return ""


def run_semgrep(pm: ProjectMap) -> list[Finding]:
    """Runs the bundled ruleset against the whole project tree. Returns []
    (rather than raising) if semgrep isn't installed or the run fails, so a
    missing/broken semgrep never breaks the rest of the security scan."""
    if not os.path.exists(RULES_PATH):
        return []
    try:
        proc = subprocess.run(
            ["semgrep", "--config", RULES_PATH, "--json", "--quiet",
             "--timeout", "90", "--max-target-bytes", "2000000", pm.root_dir],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(proc.stdout) if proc.stdout else {"results": []}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []

    findings = []
    for r in data.get("results", []):
        try:
            rel_path = os.path.relpath(r["path"], pm.root_dir)
        except Exception:
            rel_path = r.get("path", "unknown")

        start_line = r.get("start", {}).get("line", 0)
        end_line = r.get("end", {}).get("line", start_line)
        extra = r.get("extra", {})
        check_id = r.get("check_id", "semgrep").rsplit(".", 1)[-1]
        category = extra.get("metadata", {}).get("category", "semgrep")
        severity = SEMGREP_SEVERITY_MAP.get(extra.get("severity", "WARNING"), "medium")

        findings.append(Finding(
            rel_path, start_line, severity, category,
            f"[{check_id}] {extra.get('message', '').strip()}",
            _read_snippet(r["path"], start_line, end_line),
        ))
    return findings
