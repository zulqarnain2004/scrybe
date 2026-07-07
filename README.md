# Scrybe

Point it at a ZIP, a single source file, or a public GitHub repo. It maps the
project, runs real static analysis and security scanning, audits dependencies
for known CVEs, mines git history for churn/bus-factor risk, draws the module
dependency graph, and layers an AI executive summary / risk assessment /
action plan on top — all exportable as a PDF. You can also chat with the
repo directly, with every answer backed by real `file:line` citations from a
locally-run embedding index (no GPU, no external embedding API).

## Why this is more than "GitHub review + SonarQube + a chatbot"

Everything **deterministic** (complexity, maintainability, secrets, SQL
injection patterns, dependency CVEs, git churn, import cycles) is computed by
real tools (`radon`, `bandit`, `pip-audit`, `git log`, `ast`) — not guessed by
an LLM. The LLM is only used to *interpret and prioritize* that already-
verified data, and to power repo chat and doc generation. That split means
every number in the final report traces back to something you can re-run and
verify yourself.

**Features beyond a typical AI code-review demo:**
- **Dependency vulnerability audit** — `pip-audit` / curated CVE fallback for Python, `package.json` heuristic checks for Node.
- **Git churn & bus-factor analysis** — flags files that change constantly and are only ever touched by one author (a real predictor of defects, not vibes).
- **Module dependency graph** — AST-based for Python, regex-based for JS/TS, with automatic circular-import detection, rendered as an image in the UI and PDF.
- **Scan history & trend tracking** — every scan is saved to SQLite so you can see whether a codebase's risk score is improving or getting worse over time.
- **Grounded doc generation** — README and per-function docstrings are generated from the actual file tree and code excerpts, not a generic template.

## Project Structure

```
codesage/
├── app.py                      # Streamlit UI
├── backend/
│   ├── ingestion.py             # ZIP / file / GitHub → project file map
│   ├── analyzer.py              # Complexity, maintainability, tech-debt estimate (radon)
│   ├── security_scanner.py      # Secrets, SQL injection heuristics, bandit
│   ├── dependency_audit.py      # pip-audit / npm CVE checks
│   ├── git_analysis.py          # Churn, bus factor, contributor stats
│   ├── dependency_graph.py      # Import graph + cycle detection
│   ├── embeddings.py            # Local CPU embeddings + chunking for repo chat
│   ├── llm_client.py            # Anthropic API wrapper
│   ├── review_generator.py      # AI executive summary / risk / action plan
│   ├── doc_generator.py         # README + docstring generation
│   ├── chat.py                  # RAG repo chat with citations
│   ├── report_export.py         # PDF report builder (reportlab)
│   └── db.py                    # SQLite scan history
├── requirements.txt
└── data/                        # SQLite DB + embedding cache (created at runtime)
```

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

You'll need an [Anthropic API key](https://console.anthropic.com/) for the AI
review, repo chat, and doc generation features — paste it into the sidebar,
or set the `ANTHROPIC_API_KEY` environment variable. Everything else
(static analysis, security scanning, dependency audit, git churn, dependency
graph) works without a key.

The first repo-chat run downloads the `all-MiniLM-L6-v2` embedding model
(~80MB) once; after that it's cached and runs fully offline on CPU.

## Usage

1. Choose a source in the sidebar (ZIP, single file, or GitHub URL) and click **Run Full Scan**.
2. Browse the tabs: AI Review, Complexity, Security, Dependencies, Git Churn, Dependency Graph, Chat with Repo, Docs & README.
3. Ask questions about the codebase in **Chat with Repo** — answers cite the exact file and lines they came from.
4. Export everything as a single PDF from the button at the bottom of the page.

## Notes & Limitations

- SQL-injection and secret detection are pattern-based heuristics layered on top of `bandit`'s deeper Python-specific checks — they're a strong first pass, not a replacement for a dedicated SAST/DAST pipeline on critical systems.
- The dependency CVE fallback list is small and illustrative; `pip-audit` (used automatically when available) queries a live vulnerability database and should be preferred.
- Git churn analysis requires the project to be a git repo (GitHub URL ingestion) or the ZIP to include a `.git` folder.
