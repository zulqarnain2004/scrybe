"""
review_generator.py — Turns raw static-analysis, security, dependency, and
git-churn findings into an AI-written executive summary, risk assessment,
and prioritized action plan. Critically, the LLM is only asked to *interpret
and prioritize* findings we already computed deterministically — it never
invents metrics, so numbers in the final report always trace back to real
tool output (radon/bandit/pip-audit/git), not hallucination.
"""

import json
import textwrap

from .llm_client import complete

SYSTEM_PROMPT = """You are a senior staff engineer and security architect writing a code \
review report for another engineer. You are given ONLY pre-computed, tool-verified \
findings (static analysis metrics, security scan results, dependency vulnerabilities, \
git churn data). Do not invent metrics or findings that aren't in the input. Be direct, \
specific, and reference actual file names and numbers from the input. Avoid generic \
advice ("write more tests") unless it's tied to a specific finding."""


def _build_context_blob(analysis, security_findings, dependency_findings, git_result) -> str:
    top_hotspots = [
        {"file": fm.path, "complexity": fm.complexity, "maintainability": fm.maintainability_index}
        for fm in analysis.hotspots[:8]
    ]
    top_security = [
        {"file": f["file_path"], "line": f["line_number"], "severity": f["severity"],
         "category": f["category"], "description": f["description"]}
        for f in security_findings[:15]
    ]
    deps = [
        {"package": f["package_name"], "version": f["installed_version"],
         "cve": f["vulnerability_id"], "severity": f["severity"]}
        for f in dependency_findings[:10]
    ]
    churn = []
    if git_result.available:
        churn = [
            {"file": c.file_path, "commits": c.commit_count, "authors": c.author_count,
             "bus_factor_risk": c.bus_factor_risk}
            for c in git_result.churn[:8]
        ]

    context = {
        "project_metrics": {
            "total_files": analysis.total_files,
            "total_loc": analysis.total_loc,
            "avg_complexity": analysis.avg_complexity,
            "avg_maintainability_index": analysis.avg_maintainability,
            "estimated_tech_debt_hours": analysis.tech_debt_hours,
        },
        "complexity_hotspots": top_hotspots,
        "security_findings": top_security,
        "security_findings_total_count": len(security_findings),
        "dependency_vulnerabilities": deps,
        "git_churn_hotspots": churn,
    }
    return json.dumps(context, indent=2)


def generate_review(analysis, security_findings, dependency_findings, git_result, api_key: str | None = None) -> dict:
    context_blob = _build_context_blob(analysis, security_findings, dependency_findings, git_result)

    prompt = textwrap.dedent(f"""
        Here is the tool-verified analysis data for a codebase:

        {context_blob}

        Write a code review report with exactly these three sections, using markdown headers:

        ## Executive Summary
        3-5 sentences. What's the overall health of this codebase? Lead with the single
        most important thing a reviewer should know.

        ## Risk Assessment
        A prioritized list (highest risk first) of the top 5-8 concrete risks, each one
        sentence, each citing the specific file/package/metric it comes from.

        ## Action Plan
        A numbered, prioritized list of 5-8 concrete next steps, each one sentence,
        ordered by (severity x effort). Be specific about which file or dependency to fix.
    """).strip()

    text = complete(prompt, api_key=api_key, system=SYSTEM_PROMPT, max_tokens=1500)
    return _split_sections(text)


def _split_sections(text: str) -> dict:
    sections = {"executive_summary": "", "risk_assessment": "", "action_plan": "", "raw": text}
    current = None
    buf = []
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith("## executive summary"):
            if current:
                sections[current] = "\n".join(buf).strip()
            current, buf = "executive_summary", []
        elif low.startswith("## risk assessment"):
            if current:
                sections[current] = "\n".join(buf).strip()
            current, buf = "risk_assessment", []
        elif low.startswith("## action plan"):
            if current:
                sections[current] = "\n".join(buf).strip()
            current, buf = "action_plan", []
        else:
            buf.append(line)
    if current:
        sections[current] = "\n".join(buf).strip()
    return sections
