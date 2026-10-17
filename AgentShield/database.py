"""
database.py
Local SQLite audit log for AgentShield security events.

This module exists purely for security auditing/logging purposes -
it is not a general-purpose CRUD layer.
"""

import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "agentshield.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT,
    event_type TEXT,
    risk_score INTEGER,
    severity TEXT,
    decision TEXT,
    reason TEXT,
    tool_requested TEXT,
    scenario_name TEXT
);
"""


def initialize_database(db_path: str = DB_PATH) -> None:
    """Create the database file and schema if they do not already exist."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def log_event(source: str, event_type: str, risk_score: int, severity: str,
              decision: str, reason: str, tool_requested: str = "",
              scenario_name: str = "", db_path: str = DB_PATH) -> None:
    """Insert one security event into the audit log."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO security_events
               (timestamp, source, event_type, risk_score, severity,
                decision, reason, tool_requested, scenario_name)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(timespec="seconds"), source, event_type,
             int(risk_score), severity, decision, reason, tool_requested, scenario_name),
        )
        conn.commit()
    finally:
        conn.close()


def get_recent_events(limit: int = 50, db_path: str = DB_PATH) -> list:
    """Return the most recent security events, newest first."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def clear_events(db_path: str = DB_PATH) -> None:
    """Delete all stored security events (used for demo resets)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM security_events")
        conn.commit()
    finally:
        conn.close()
