"""
Scrybe — Streamlit UI

Point it at a ZIP, a single source file, or a public GitHub URL. It maps the
project, runs static analysis, security scanning, dependency auditing, git
churn analysis, and a module dependency graph — all deterministic, tool-based.
Then it layers an AI review, README/docstring generation, and RAG chat with
file:line citations on top, backed by local CPU embeddings.
"""

import os
import sys
import json
import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))

from backend import db
from backend.ingestion import (
    make_workdir, cleanup_workdir, ingest_zip, ingest_single_file, ingest_github,
    build_project_map, IngestionError,
)
from backend.analyzer import analyze_project, AnalysisResult, FileMetric, COMPLEXITY_THRESHOLD, MIN_MAINTAINABILITY
from backend.security_scanner import run_full_security_scan, findings_to_dicts as sec_dicts
from backend.dependency_audit import run_dependency_audit, findings_to_dicts as dep_dicts
from backend.git_analysis import analyze_git_history, GitAnalysisResult
from backend.dependency_graph import build_dependency_graph, DependencyGraphResult
from backend.review_generator import generate_review
from backend.doc_generator import generate_readme, generate_missing_docstrings
from backend.embeddings import build_or_load_index
from backend.chat import answer_question
from backend.report_export import build_pdf_report
from backend.sarif_export import build_sarif
from backend.duplication_detector import find_duplicates, duplicates_to_dicts
from backend.fix_suggester import suggest_security_fix, dependency_fix_action, read_file_context
from backend.notifier import send_scan_complete_email, NotifierError
from backend.llm_client import LLMNotConfigured, LLMRequestError

st.set_page_config(page_title="Scrybe", page_icon="🧠", layout="wide")
db.init_db()

# --- Session state ---
for key, default in [
    ("scan_result", None), ("project_map", None), ("scan_id", None),
    ("embedding_index", None), ("chat_messages", []), ("readme_text", None),
]:
    if key not in st.session_state:
        st.session_state[key] = default


# --- Sidebar: input + config ---
def _load_historical_scan(scan_id: int):
    """Reconstruct a past scan from the DB for read-only viewing. Git churn and
    the dependency graph aren't persisted (only current-session data), so those
    tabs show as unavailable for historical scans. Chat/README/docstrings need
    the actual source files, so they're disabled too — only a fresh scan of the
    same source restores those."""
    scan_row = db.get_scan(scan_id)
    if not scan_row:
        st.error("That scan could not be found (it may have been deleted).")
        return

    file_rows = db.get_file_metrics(scan_id)
    file_metrics = [
        FileMetric(
            path=r["file_path"], language="", loc=r["loc"] or 0,
            complexity=r["complexity"] or 0.0, maintainability_index=r["maintainability_index"] or 0.0,
            function_count=0, functions=[],
        )
        for r in file_rows
    ]
    analysis = AnalysisResult(
        file_metrics=file_metrics,
        total_files=scan_row["total_files"] or 0,
        total_loc=scan_row["total_loc"] or 0,
        avg_complexity=scan_row["avg_complexity"] or 0.0,
        avg_maintainability=scan_row["avg_maintainability"] or 0.0,
        tech_debt_hours=scan_row["tech_debt_hours"] or 0.0,
        hotspots=sorted(file_metrics, key=lambda fm: (fm.complexity, -fm.maintainability_index), reverse=True)[:10],
    )
    review = json.loads(scan_row["summary_json"]) if scan_row["summary_json"] else {
        "executive_summary": "", "risk_assessment": "", "action_plan": "",
    }

    st.session_state.scan_result = {
        "project_name": scan_row["project_name"], "analysis": analysis,
        "security_findings": db.get_security_findings(scan_id),
        "dependency_findings": db.get_dependency_findings(scan_id),
        "git_result": GitAnalysisResult(reason_unavailable="Historical scan — git history isn't stored between sessions. Re-run a scan to see it."),
        "graph_result": DependencyGraphResult(),
        "duplicate_groups": [],
        "review": review, "risk_score": scan_row["risk_score"] or 0.0,
        "is_historical": True,
    }
    st.session_state.project_map = None
    st.session_state.scan_id = scan_id
    st.session_state.embedding_index = None
    st.session_state.chat_messages = []
    st.session_state.readme_text = None


with st.sidebar:
    st.title("🧠 Scrybe")
    st.caption("Code review, security, and repo chat — in one pass.")

    api_key = st.text_input("Anthropic API key", type="password", value=os.environ.get("ANTHROPIC_API_KEY", ""))
    st.divider()

    source_type = st.radio("Source", ["ZIP upload", "Single file", "GitHub URL"])
    uploaded_zip, uploaded_file, github_url = None, None, ""

    if source_type == "ZIP upload":
        uploaded_zip = st.file_uploader("Upload a .zip", type=["zip"])
    elif source_type == "Single file":
        uploaded_file = st.file_uploader("Upload a source file")
    else:
        github_url = st.text_input("Public GitHub URL", placeholder="https://github.com/owner/repo")

    run_scan = st.button("🔍 Run Full Scan", type="primary", width="stretch")

    with st.expander("📧 Email notification on completion"):
        notify_email = st.checkbox("Email me when the scan finishes", value=False)
        notify_to = st.text_input("Recipient email", value=os.environ.get("NOTIFY_EMAIL_TO", ""))
        smtp_host = st.text_input("SMTP host", value=os.environ.get("SMTP_HOST", ""), placeholder="smtp.gmail.com")
        smtp_port = st.number_input("SMTP port", value=int(os.environ.get("SMTP_PORT", 587)), step=1)
        smtp_user = st.text_input("SMTP username", value=os.environ.get("SMTP_USER", ""))
        smtp_password = st.text_input("SMTP password", value=os.environ.get("SMTP_PASSWORD", ""), type="password")
        smtp_use_tls = st.checkbox("Use STARTTLS", value=True)
        st.caption("Gmail: use an App Password, not your regular password. Settings aren't saved between sessions.")

    st.divider()
    st.caption("Past scans")
    for s in db.list_scans()[:8]:
        if st.button(f"{s['project_name']} — risk {s['risk_score']:.0f}", key=f"hist_{s['id']}"):
            _load_historical_scan(s["id"])


_SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}


def _risk_score(analysis, security_findings, dependency_findings) -> float:
    """0-100 composite risk score — transparent weighted sum, not a black box."""
    sec_score = sum(_SEVERITY_WEIGHTS.get(f["severity"], 0) for f in security_findings)
    dep_score = sum(_SEVERITY_WEIGHTS.get(f["severity"], 0) for f in dependency_findings)
    complexity_penalty = max(0, analysis.avg_complexity - 5) * 3
    maintainability_penalty = max(0, 70 - analysis.avg_maintainability) * 0.5
    raw = sec_score + dep_score + complexity_penalty + maintainability_penalty
    return min(100.0, raw)


def run_full_scan():
    workdir = make_workdir()
    try:
        try:
            with st.spinner("Ingesting project..."):
                if source_type == "ZIP upload" and uploaded_zip:
                    zip_path = os.path.join(workdir, "upload.zip")
                    with open(zip_path, "wb") as f:
                        f.write(uploaded_zip.getbuffer())
                    root_dir = ingest_zip(zip_path, workdir)
                    project_name, source_ref = uploaded_zip.name.rsplit(".", 1)[0], uploaded_zip.name
                elif source_type == "Single file" and uploaded_file:
                    tmp_path = os.path.join(workdir, uploaded_file.name)
                    with open(tmp_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    root_dir = ingest_single_file(tmp_path, workdir, uploaded_file.name)
                    project_name, source_ref = uploaded_file.name, uploaded_file.name
                elif source_type == "GitHub URL" and github_url:
                    root_dir = ingest_github(github_url, workdir)
                    project_name = github_url.rstrip("/").split("/")[-1]
                    if project_name.endswith(".git"):
                        project_name = project_name[:-len(".git")]
                    source_ref = github_url
                else:
                    st.error("Please provide a source before running a scan.")
                    return

                pm = build_project_map(root_dir, project_name)
                if not pm.files:
                    st.error("No recognizable source files found in the project.")
                    return
        except IngestionError as e:
            st.error(str(e))
            return

        with st.spinner(f"Running static analysis on {len(pm.files)} files..."):
            analysis = analyze_project(pm)

        with st.spinner("Scanning for security issues..."):
            security_findings = sec_dicts(run_full_security_scan(pm))

        with st.spinner("Auditing dependencies for known vulnerabilities..."):
            dependency_findings = dep_dicts(run_dependency_audit(pm))

        with st.spinner("Analyzing git history..."):
            git_result = analyze_git_history(pm)

        with st.spinner("Building module dependency graph..."):
            graph_result = build_dependency_graph(pm)

        with st.spinner("Scanning for duplicated code..."):
            duplicate_groups = duplicates_to_dicts(find_duplicates(pm))

        risk_score = _risk_score(analysis, security_findings, dependency_findings)

        review = {"executive_summary": "", "risk_assessment": "", "action_plan": ""}
        if api_key:
            try:
                with st.spinner("Generating AI review..."):
                    review = generate_review(analysis, security_findings, dependency_findings, git_result, api_key=api_key)
            except LLMNotConfigured:
                st.warning("AI review skipped — no API key configured.")
            except LLMRequestError as e:
                st.error(str(e))
            except Exception as e:
                st.warning(f"AI review failed: {e}")

        embedding_index = None
        if api_key:
            try:
                with st.spinner("Building local embedding index for repo chat..."):
                    embedding_index = build_or_load_index(pm)
            except ImportError:
                st.info("Install `sentence-transformers` to enable repo chat.")
            except Exception as e:
                st.warning(f"Embedding index failed: {e}")

        metrics = {
            "total_files": analysis.total_files, "total_loc": analysis.total_loc,
            "avg_complexity": analysis.avg_complexity, "avg_maintainability": analysis.avg_maintainability,
            "tech_debt_hours": analysis.tech_debt_hours, "risk_score": risk_score,
        }
        scan_id = db.save_scan(project_name, source_type, source_ref, metrics, review)
        db.save_file_metrics(scan_id, [
            {"file_path": fm.path, "loc": fm.loc, "complexity": fm.complexity,
             "maintainability_index": fm.maintainability_index}
            for fm in analysis.file_metrics
        ])
        db.save_security_findings(scan_id, security_findings)
        db.save_dependency_findings(scan_id, dependency_findings)

        st.session_state.scan_result = {
            "project_name": project_name, "analysis": analysis,
            "security_findings": security_findings, "dependency_findings": dependency_findings,
            "git_result": git_result, "graph_result": graph_result,
            "duplicate_groups": duplicate_groups,
            "review": review, "risk_score": risk_score,
        }
        st.session_state.project_map = pm
        st.session_state.scan_id = scan_id
        st.session_state.embedding_index = embedding_index
        st.session_state.chat_messages = []
        st.session_state.readme_text = None

        if notify_email:
            try:
                with st.spinner("Sending notification email..."):
                    send_scan_complete_email(
                        smtp_host, int(smtp_port), smtp_user, smtp_password, notify_to,
                        project_name, risk_score, security_findings, dependency_findings,
                        use_tls=smtp_use_tls,
                    )
                st.success(f"Notification email sent to {notify_to}.")
            except NotifierError as e:
                st.warning(f"Scan finished, but the notification email failed: {e}")
    finally:
        cleanup_workdir(workdir)


if run_scan:
    run_full_scan()

result = st.session_state.scan_result
if result is None:
    st.info("👈 Configure a source in the sidebar and click **Run Full Scan** to get started.")
    st.stop()

analysis = result["analysis"]
security_findings = result["security_findings"]
dependency_findings = result["dependency_findings"]
git_result = result["git_result"]
graph_result = result["graph_result"]
duplicate_groups = result.get("duplicate_groups", [])
review = result["review"]

st.title(f"📊 {result['project_name']}")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Files", analysis.total_files)
col2.metric("Lines of Code", analysis.total_loc)
col3.metric("Avg Complexity", analysis.avg_complexity)
col4.metric("Maintainability", analysis.avg_maintainability)
col5.metric("Risk Score", f"{result['risk_score']:.0f}/100")

tabs = st.tabs([
    "AI Review", "Complexity", "Security", "Dependencies", "Duplication",
    "Git Churn", "Dependency Graph", "Chat with Repo", "Docs & README",
])

with tabs[0]:
    if review.get("executive_summary"):
        st.subheader("Executive Summary")
        st.write(review["executive_summary"])
        st.subheader("Risk Assessment")
        st.write(review["risk_assessment"])
        st.subheader("Action Plan")
        st.write(review["action_plan"])
    else:
        st.info("Add an Anthropic API key in the sidebar and re-run the scan to generate the AI review.")

with tabs[1]:
    st.subheader("Complexity Hotspots")
    st.dataframe(
        [{"File": fm.path, "Complexity": fm.complexity, "Maintainability": fm.maintainability_index,
          "Functions": fm.function_count, "LOC": fm.loc} for fm in analysis.hotspots],
        width="stretch",
    )
    st.caption(f"Estimated tech debt: **{analysis.tech_debt_hours} hours** "
               f"(complexity > {COMPLEXITY_THRESHOLD} or maintainability < {MIN_MAINTAINABILITY})")

_SNIPPET_LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cs": "csharp", ".rs": "rust",
    ".sql": "sql", ".sh": "bash", ".yaml": "yaml", ".yml": "yaml", ".json": "json",
}


def _snippet_language(file_path: str) -> str:
    _, ext = os.path.splitext(file_path)
    return _SNIPPET_LANG_BY_EXT.get(ext.lower(), "text")


with tabs[2]:
    st.subheader(f"Security Findings ({len(security_findings)})")
    severity_filter = st.multiselect("Filter by severity", ["critical", "high", "medium", "low"],
                                      default=["critical", "high", "medium", "low"])
    st.session_state.setdefault("fix_suggestions", {})
    for i, f in enumerate([f for f in security_findings if f["severity"] in severity_filter]):
        badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}[f["severity"]]
        st.markdown(f"{badge} **{f['description']}** — `{f['file_path']}:{f['line_number']}`")
        with st.expander("Show snippet"):
            st.code(f["snippet"], language=_snippet_language(f["file_path"]))
        fix_key = f"{f['file_path']}:{f['line_number']}:{f['description']}"
        col_a, _ = st.columns([1, 5])
        with col_a:
            if st.button("💡 Suggest fix", key=f"fixbtn_{i}_{fix_key}"):
                if not api_key:
                    st.warning("Add an API key first.")
                else:
                    try:
                        context = ""
                        if st.session_state.project_map is not None:
                            for pf in st.session_state.project_map.files:
                                if pf.path == f["file_path"]:
                                    context = read_file_context(pf.abs_path, f["line_number"])
                                    break
                        with st.spinner("Asking Claude for a fix..."):
                            suggestion = suggest_security_fix(f, context=context, api_key=api_key)
                        st.session_state.fix_suggestions[fix_key] = suggestion
                    except LLMRequestError as e:
                        st.error(str(e))
                    except LLMNotConfigured as e:
                        st.warning(str(e))
        if fix_key in st.session_state.fix_suggestions:
            st.markdown(st.session_state.fix_suggestions[fix_key])
        st.divider()

with tabs[3]:
    st.subheader(f"Dependency Vulnerabilities ({len(dependency_findings)})")
    if dependency_findings:
        st.dataframe(
            [{**f, "Suggested Fix": dependency_fix_action(f)} for f in dependency_findings],
            width="stretch",
        )
    else:
        st.success("No known-vulnerable dependency versions detected.")

with tabs[4]:
    st.subheader(f"Duplicate Code ({len(duplicate_groups)} groups)")
    if result.get("is_historical"):
        st.info("Not available for historical scans (not persisted between sessions). Re-run a scan to see this.")
    elif duplicate_groups:
        st.caption("Line/token-based clone detection — copy-pasted blocks that could be extracted into a shared function.")
        for g in duplicate_groups:
            st.markdown(
                f"**{g['line_count']} lines** duplicated: "
                f"`{g['file_a']}:{g['lines_a']}` ↔ `{g['file_b']}:{g['lines_b']}`"
            )
            with st.expander("Preview"):
                st.code(g["preview"])
    else:
        st.success("No significant duplicate code blocks detected.")

with tabs[5]:
    st.subheader("Git Churn & Bus Factor")
    if git_result.available:
        st.caption(f"{git_result.total_commits} commits analyzed across {len(git_result.contributors)} contributors.")
        st.dataframe(
            [{"File": c.file_path, "Commits": c.commit_count, "Authors": c.author_count,
              "Bus Factor Risk": "⚠️ Yes" if c.bus_factor_risk else "No",
              "Last modified (days ago)": c.last_modified_days_ago}
             for c in git_result.churn],
            width="stretch",
        )
    else:
        st.info(git_result.reason_unavailable)

with tabs[6]:
    st.subheader("Module Dependency Graph")
    if graph_result.image_bytes:
        st.image(graph_result.image_bytes, width="stretch")
        if graph_result.cycles:
            st.warning("Circular imports detected:\n" + "\n".join(
                "→ ".join(cyc) for cyc in graph_result.cycles
            ))
        if graph_result.most_depended_on:
            st.caption("Most depended-on modules: " + ", ".join(
                f"{m} ({d})" for m, d in graph_result.most_depended_on[:5]
            ))
    else:
        st.info("No resolvable import graph (single-file project or unsupported languages only).")

with tabs[7]:
    st.subheader("💬 Chat with the Repo")
    if st.session_state.embedding_index is None:
        if result.get("is_historical"):
            st.info("Not available for historical scans (source files aren't retained between sessions). Re-run a scan on the same source to use this.")
        else:
            st.info("Add an API key and re-run the scan to enable repo chat (requires `sentence-transformers`).")
    else:
        for msg in st.session_state.chat_messages:
            with st.chat_message(msg["role"]):
                st.write(msg["content"])
                if msg.get("citations"):
                    with st.expander("Citations"):
                        for c in msg["citations"]:
                            st.code(f"{c['file_path']}:{c['start_line']}-{c['end_line']} "
                                     f"(relevance {c['relevance_score']})")

        question = st.chat_input("Ask about this codebase...")
        if question:
            st.session_state.chat_messages.append({"role": "user", "content": question})
            db.save_chat_message(st.session_state.scan_id, "user", question)
            try:
                with st.spinner("Searching the repo..."):
                    answer = answer_question(question, st.session_state.embedding_index, api_key=api_key)
                st.session_state.chat_messages.append({
                    "role": "assistant", "content": answer.text, "citations": answer.citations,
                })
                db.save_chat_message(st.session_state.scan_id, "assistant", answer.text, answer.citations)
            except LLMRequestError as e:
                st.error(str(e))
            except LLMNotConfigured as e:
                st.warning(str(e))
            st.rerun()

with tabs[8]:
    st.subheader("README Generator")
    if st.session_state.project_map is None:
        st.info("Not available for historical scans (source files aren't retained between sessions). Re-run a scan to use this.")
    elif st.button("Generate README.md"):
        if not api_key:
            st.warning("Add an API key first.")
        else:
            try:
                with st.spinner("Writing README from actual project structure..."):
                    st.session_state.readme_text = generate_readme(st.session_state.project_map, analysis, api_key=api_key)
            except LLMRequestError as e:
                st.error(str(e))
            except LLMNotConfigured as e:
                st.warning(str(e))
    if st.session_state.readme_text:
        st.code(st.session_state.readme_text, language="markdown")
        st.download_button("Download README.md", st.session_state.readme_text, file_name="README.md")

    st.divider()
    st.subheader("Missing Docstrings")
    if st.session_state.project_map is None:
        st.info("Not available for historical scans (source files aren't retained between sessions). Re-run a scan to use this.")
    else:
        max_funcs = st.slider("Max functions to document", 5, 50, 20)
        if st.button("Generate Missing Docstrings"):
            if not api_key:
                st.warning("Add an API key first.")
            else:
                docs = None
                try:
                    with st.spinner("Finding undocumented functions and writing docstrings..."):
                        docs = generate_missing_docstrings(st.session_state.project_map, max_functions=max_funcs, api_key=api_key)
                except LLMRequestError as e:
                    st.error(str(e))
                except LLMNotConfigured as e:
                    st.warning(str(e))
                if docs:
                    for d in docs:
                        st.markdown(f"**{d['file_path']}** — `{d['symbol_name']}` (line {d['line']})")
                        st.code(d["generated_docstring"])
                elif docs is not None:
                    st.success("No missing docstrings found (or none in the scanned languages).")

st.divider()
col_pdf, col_sarif = st.columns(2)
with col_pdf:
    if st.button("📄 Export Full PDF Report", type="primary"):
        with st.spinner("Building PDF..."):
            pdf_bytes = build_pdf_report(
                result["project_name"], analysis, security_findings, dependency_findings,
                git_result, graph_result, review,
            )
        st.download_button("Download PDF Report", pdf_bytes, file_name=f"{result['project_name']}_scrybe_report.pdf",
                            mime="application/pdf")
with col_sarif:
    if st.button("🛡️ Export SARIF (for GitHub code scanning)"):
        sarif_str = build_sarif(security_findings, dependency_findings)
        st.download_button("Download SARIF", sarif_str, file_name=f"{result['project_name']}_scrybe.sarif",
                            mime="application/sarif+json")
