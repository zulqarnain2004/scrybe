"""
db.py — SQLite persistence layer for CodeSage AI.

Stores scan history, per-file metrics, security findings, and chat sessions
so users can track how a codebase evolves across scans (a feature the
original CodeSage post didn't mention).
"""

import sqlite3
import json
import time
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent.parent / "data" / "codesage.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT NOT NULL,
    source_type TEXT NOT NULL,      -- 'zip' | 'file' | 'github'
    source_ref TEXT,                -- github url or filename
    created_at REAL NOT NULL,
    total_files INTEGER,
    total_loc INTEGER,
    avg_complexity REAL,
    avg_maintainability REAL,
    tech_debt_hours REAL,
    risk_score REAL,
    summary_json TEXT               -- full JSON blob of the scan result
);

CREATE TABLE IF NOT EXISTS file_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    loc INTEGER,
    complexity REAL,
    maintainability_index REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS security_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    severity TEXT,                  -- 'critical' | 'high' | 'medium' | 'low'
    category TEXT,                  -- 'secret' | 'sql_injection' | 'bandit' | 'dependency'
    description TEXT,
    snippet TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS chat_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    role TEXT NOT NULL,             -- 'user' | 'assistant'
    content TEXT NOT NULL,
    citations_json TEXT,
    created_at REAL NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS dependency_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    package_name TEXT,
    installed_version TEXT,
    ecosystem TEXT,                 -- 'pypi' | 'npm'
    vulnerability_id TEXT,
    severity TEXT,
    description TEXT,
    fix_version TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_scan(project_name, source_type, source_ref, metrics: dict, summary: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans
               (project_name, source_type, source_ref, created_at, total_files,
                total_loc, avg_complexity, avg_maintainability, tech_debt_hours,
                risk_score, summary_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                project_name, source_type, source_ref, time.time(),
                metrics.get("total_files", 0), metrics.get("total_loc", 0),
                metrics.get("avg_complexity", 0.0), metrics.get("avg_maintainability", 0.0),
                metrics.get("tech_debt_hours", 0.0), metrics.get("risk_score", 0.0),
                json.dumps(summary),
            ),
        )
        return cur.lastrowid


def save_file_metrics(scan_id: int, file_rows: list[dict]):
    with get_conn() as conn:
        conn.executemany(
            """INSERT INTO file_metrics (scan_id, file_path, loc, complexity, maintainability_index)
               VALUES (:scan_id, :file_path, :loc, :complexity, :maintainability_index)""",
            [{**row, "scan_id": scan_id} for row in file_rows],
        )


def save_security_findings(scan_id: int, findings: list[dict]):
    with get_conn() as conn:
        conn.executemany(
            """INSERT INTO security_findings
               (scan_id, file_path, line_number, severity, category, description, snippet)
               VALUES (:scan_id, :file_path, :line_number, :severity, :category, :description, :snippet)""",
            [{**f, "scan_id": scan_id} for f in findings],
        )


def save_dependency_findings(scan_id: int, findings: list[dict]):
    with get_conn() as conn:
        conn.executemany(
            """INSERT INTO dependency_findings
               (scan_id, package_name, installed_version, ecosystem, vulnerability_id,
                severity, description, fix_version)
               VALUES (:scan_id, :package_name, :installed_version, :ecosystem,
                       :vulnerability_id, :severity, :description, :fix_version)""",
            [{**f, "scan_id": scan_id} for f in findings],
        )


def save_chat_message(scan_id: int, role: str, content: str, citations: list | None = None):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO chat_history (scan_id, role, content, citations_json, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (scan_id, role, content, json.dumps(citations or []), time.time()),
        )


def get_chat_history(scan_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM chat_history WHERE scan_id = ? ORDER BY created_at ASC", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def list_scans(project_name: str | None = None) -> list[dict]:
    with get_conn() as conn:
        if project_name:
            rows = conn.execute(
                "SELECT * FROM scans WHERE project_name = ? ORDER BY created_at DESC", (project_name,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_file_metrics(scan_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM file_metrics WHERE scan_id = ? ORDER BY complexity DESC", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_security_findings(scan_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT file_path, line_number, severity, category, description, snippet "
            "FROM security_findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_dependency_findings(scan_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT package_name, installed_version, ecosystem, vulnerability_id, "
            "severity, description, fix_version FROM dependency_findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_trend(project_name: str) -> list[dict]:
    """Return risk_score / tech_debt_hours over time for a project, for the trend chart."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT created_at, risk_score, tech_debt_hours, avg_complexity, avg_maintainability
               FROM scans WHERE project_name = ? ORDER BY created_at ASC""",
            (project_name,),
        ).fetchall()
        return [dict(r) for r in rows]
