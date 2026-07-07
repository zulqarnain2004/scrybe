"""
fix_suggester.py — Turns a finding into something actionable.

Dependency findings already carry a known-safe version from the audit, so the
fix is deterministic (an upgrade command) — no LLM call needed, no cost, no
hallucination risk.

Security findings (secrets/SQLi/bandit/semgrep) get an LLM-generated patch
suggestion, on demand (one API call per "Suggest fix" click, not automatically
for every finding on every scan) to keep cost and latency predictable.
"""

from .llm_client import complete

FIX_SYSTEM_PROMPT = (
    "You are a senior application security engineer. Given a single static-analysis "
    "finding (file, line, description, and the offending code snippet, plus a few lines "
    "of surrounding context when available), respond with:\n"
    "1. A one-sentence explanation of *why* it's a risk.\n"
    "2. A corrected code snippet (just the relevant lines, not the whole file) using "
    "a fenced code block.\n"
    "Be concrete and specific to the actual snippet shown — don't give generic advice. "
    "If the fix requires a specific library (e.g. parameterized queries, a safe YAML "
    "loader, an allowlist), name it. Keep the whole response under 150 words."
)


def suggest_security_fix(finding: dict, context: str = "", api_key: str | None = None) -> str:
    """finding: one dict from security_scanner.findings_to_dicts(). context: optional
    wider excerpt of the file (a handful of lines around the finding) for better fixes
    than the single-line snippet alone can give."""
    prompt = (
        f"File: {finding.get('file_path')}\n"
        f"Line: {finding.get('line_number')}\n"
        f"Category: {finding.get('category')}\n"
        f"Finding: {finding.get('description')}\n\n"
        f"Offending line:\n```\n{finding.get('snippet', '')}\n```\n"
    )
    if context:
        prompt += f"\nSurrounding context:\n```\n{context}\n```\n"
    return complete(prompt, api_key=api_key, system=FIX_SYSTEM_PROMPT, max_tokens=500)


def dependency_fix_action(finding: dict) -> str:
    """Deterministic upgrade command — no LLM involved, the safe version is
    already known from the audit itself."""
    fix_version = finding.get("fix_version") or "latest"
    pkg = finding.get("package_name", "")
    if finding.get("ecosystem") == "npm":
        return f"npm install {pkg}@{fix_version}"
    return f"pip install {pkg}=={fix_version}"


def read_file_context(abs_path: str, line_number: int, radius: int = 5) -> str:
    """Reads `radius` lines of surrounding source around line_number (1-indexed).
    Returns '' if the file can't be read — callers should treat that as
    'no extra context available', not an error."""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return ""
    start = max(0, line_number - 1 - radius)
    end = min(len(lines), line_number + radius)
    return "".join(lines[start:end])
