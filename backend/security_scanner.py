"""
security_scanner.py — Flags hardcoded secrets (regex + Shannon entropy),
SQL injection patterns (string-built queries), and runs `bandit` for deeper
Python-specific static security analysis (hundreds of CWE-mapped checks
we'd never hand-roll well ourselves).
"""

import re
import os
import json
import math
import subprocess
from dataclasses import dataclass

from .ingestion import ProjectMap

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    file_path: str
    line_number: int
    severity: str
    category: str
    description: str
    snippet: str


# --- Secret detection -------------------------------------------------------

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]")),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Generic Password Assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
    ("JWT-looking Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Anthropic/OpenAI Key", re.compile(r"(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9\-]{20,})")),
]

SAFE_PLACEHOLDER_HINTS = ("xxxx", "your_", "changeme", "example", "<", "insert_", "placeholder")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / len(s)
        entropy -= p * math.log2(p)
    return entropy


HIGH_ENTROPY_ASSIGNMENT = re.compile(r"""['"]([A-Za-z0-9+/_\-=]{20,})['"]""")


def scan_secrets(pm: ProjectMap) -> list[Finding]:
    findings = []
    for pf in pm.files:
        if pf.language in ("Markdown",):
            continue
        try:
            with open(pf.abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue

        for i, line in enumerate(lines, start=1):
            lower = line.lower()
            if any(hint in lower for hint in SAFE_PLACEHOLDER_HINTS):
                continue

            for name, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        pf.path, i, "critical", "secret",
                        f"Possible hardcoded secret: {name}",
                        line.strip()[:160],
                    ))
                    break
            else:
                # entropy-based fallback for high-entropy quoted strings assigned to a variable
                m = HIGH_ENTROPY_ASSIGNMENT.search(line)
                if m and ("=" in line or ":" in line) and _shannon_entropy(m.group(1)) > 4.3:
                    findings.append(Finding(
                        pf.path, i, "medium", "secret",
                        "High-entropy string assigned to a variable — possible unlabeled secret",
                        line.strip()[:160],
                    ))
    return findings


# --- SQL injection heuristics ------------------------------------------------

SQL_KEYWORDS = re.compile(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.+\b(FROM|INTO|SET)\b")
STRING_CONCAT_QUERY = re.compile(r"""(?i)(SELECT|INSERT|UPDATE|DELETE)[^"'\n]*['"]\s*(\+|\%s?|\.format\(|f["'])""")
FSTRING_QUERY = re.compile(r"""(?i)f['"].*(SELECT|INSERT|UPDATE|DELETE)\b.*\{.*\}.*['"]""")
PERCENT_FORMAT_QUERY = re.compile(r"""(?i)['"].*(SELECT|INSERT|UPDATE|DELETE)\b.*%s.*['"]\s*%""")
PARAMETERIZED_HINTS = ("?", "%s", ":param", "$1")


def scan_sql_injection(pm: ProjectMap) -> list[Finding]:
    findings = []
    code_langs = {"Python", "JavaScript", "TypeScript", "Java", "PHP", "Ruby", "Go", "C#"}
    for pf in pm.files:
        if pf.language not in code_langs:
            continue
        try:
            with open(pf.abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue

        for i, line in enumerate(lines, start=1):
            if not SQL_KEYWORDS.search(line):
                continue
            is_fstring_query = bool(FSTRING_QUERY.search(line))
            is_concat_query = "+" in line and re.search(r"""['"].*\+|\+.*['"]""", line)
            is_percent_query = bool(PERCENT_FORMAT_QUERY.search(line))
            is_format_call = ".format(" in line

            if is_fstring_query or is_percent_query or is_format_call or (is_concat_query and SQL_KEYWORDS.search(line)):
                findings.append(Finding(
                    pf.path, i, "high", "sql_injection",
                    "SQL query appears to be built via string interpolation/concatenation "
                    "instead of parameterized queries — potential SQL injection",
                    line.strip()[:160],
                ))
    return findings


# --- Bandit integration (Python-specific deep static analysis) -------------

BANDIT_SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_bandit(pm: ProjectMap) -> list[Finding]:
    python_files = [pf.abs_path for pf in pm.files if pf.language == "Python"]
    if not python_files:
        return []
    try:
        proc = subprocess.run(
            ["bandit", "-f", "json", "-q", *python_files],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(proc.stdout) if proc.stdout else {"results": []}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []

    findings = []
    for r in data.get("results", []):
        try:
            rel_path = os.path.relpath(r["filename"], pm.root_dir)
        except Exception:
            rel_path = r.get("filename", "unknown")
        findings.append(Finding(
            rel_path, r.get("line_number", 0),
            BANDIT_SEVERITY_MAP.get(r.get("issue_severity", "LOW"), "low"),
            "bandit",
            f"[{r.get('test_id')}] {r.get('issue_text', '')}",
            r.get("code", "").strip().splitlines()[0][:160] if r.get("code") else "",
        ))
    return findings


def run_full_security_scan(pm: ProjectMap) -> list[Finding]:
    from .semgrep_scanner import run_semgrep
    findings = scan_secrets(pm) + scan_sql_injection(pm) + run_bandit(pm) + run_semgrep(pm)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return findings


def findings_to_dicts(findings: list[Finding]) -> list[dict]:
    return [
        {
            "file_path": f.file_path, "line_number": f.line_number, "severity": f.severity,
            "category": f.category, "description": f.description, "snippet": f.snippet,
        }
        for f in findings
    ]
