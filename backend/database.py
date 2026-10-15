"""
Velbrix - Database layer (SQLite)
"""
import sqlite3
import json
from pathlib import Path
from typing import Optional
from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_name TEXT,
    created_at TEXT,
    status TEXT,
    stack TEXT,
    file_count INTEGER,
    overall_score INTEGER,
    decision TEXT,
    category_scores TEXT,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    fid TEXT,
    title TEXT,
    severity TEXT,
    category TEXT,
    file TEXT,
    line INTEGER,
    evidence TEXT,
    description TEXT,
    why_it_matters TEXT,
    recommended_fix TEXT,
    scanner_source TEXT,
    confidence REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS patches (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    finding_id TEXT,
    before_code TEXT,
    after_code TEXT,
    diff TEXT,
    status TEXT,
    provider TEXT,
    created_at TEXT,
    verification TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS agent_actions (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    action TEXT,
    decision TEXT,
    reason TEXT,
    policy_rule TEXT,
    evidence TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS session_tests (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    check_name TEXT,
    result TEXT,
    evidence TEXT,
    created_at TEXT
);
"""


def get_db() -> sqlite3.Connection:
    db_path = settings.db_path_full
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
