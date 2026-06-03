"""
database.py — DroidScout
SQLite persistence layer for acquisition sessions and records.
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "droidscout.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist, and migrate existing schema."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT    UNIQUE NOT NULL,
                device_id       TEXT    NOT NULL,
                status          TEXT    NOT NULL DEFAULT 'starting',
                message         TEXT,
                output_dir      TEXT,
                device_info     TEXT,
                manifest        TEXT,
                case_number     TEXT,
                investigator    TEXT,
                notes           TEXT,
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL
            )
        """)
        # Migrate: add new columns to existing tables if they don't exist
        existing = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
        for col, typedef in [
            ("case_number",  "TEXT"),
            ("investigator", "TEXT"),
            ("notes",        "TEXT"),
        ]:
            if col not in existing:
                conn.execute(f"ALTER TABLE sessions ADD COLUMN {col} {typedef}")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_flags (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                device_id   TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'INFO',
                note        TEXT,
                created_at  TEXT NOT NULL,
                UNIQUE(session_id, file_path)
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def create_session(session_id: str, device_id: str, output_dir: str):
    """Insert a new session record when acquisition starts."""
    now = datetime.now().isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions (session_id, device_id, status, message, output_dir, created_at, updated_at)
            VALUES (?, ?, 'starting', 'Initializing...', ?, ?, ?)
            """,
            (session_id, device_id, output_dir, now, now),
        )
        conn.commit()


def update_session(session_id: str, status: str, message: str,
                   manifest: dict = None, device_info: dict = None):
    """Update status/message (and optionally manifest/device_info) for a session."""
    now = datetime.now().isoformat()
    with get_connection() as conn:
        if manifest is not None or device_info is not None:
            conn.execute(
                """
                UPDATE sessions
                SET status=?, message=?, manifest=?, device_info=?, updated_at=?
                WHERE session_id=?
                """,
                (
                    status,
                    message,
                    json.dumps(manifest) if manifest is not None else None,
                    json.dumps(device_info) if device_info is not None else None,
                    now,
                    session_id,
                ),
            )
        else:
            conn.execute(
                "UPDATE sessions SET status=?, message=?, updated_at=? WHERE session_id=?",
                (status, message, now, session_id),
            )
        conn.commit()


def update_case_metadata(session_id: str, case_number: str = None,
                          investigator: str = None, notes: str = None):
    """Update case-level metadata for a session."""
    now = datetime.now().isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE sessions
            SET case_number=?, investigator=?, notes=?, updated_at=?
            WHERE session_id=?
            """,
            (case_number, investigator, notes, now, session_id),
        )
        conn.commit()

def delete_session(session_id: str, device_id: str):
    """Remove a session record from the database."""
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE session_id=? AND device_id=?",
            (session_id, device_id),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def get_session(session_id: str) -> dict | None:
    """Return a single session as a dict, or None if not found."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_all_records() -> dict:
    """
    Return all sessions grouped by device_id.

    Format: { device_id: [ session_summary, ... ] }
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC"
        ).fetchall()

    records: dict = {}
    for row in rows:
        d = _row_to_dict(row)
        did = d["device_id"]
        records.setdefault(did, []).append({
            "session_id":   d["session_id"],
            "status":       d["status"],
            "timestamp":    d["created_at"],
            "device_info":  json.loads(d["device_info"]) if d["device_info"] else None,
            "path":         d["output_dir"],
            "case_number":  d.get("case_number"),
            "investigator": d.get("investigator"),
            "notes":        d.get("notes"),
        })
    return records


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


# ---------------------------------------------------------------------------
# File flags
# ---------------------------------------------------------------------------

def upsert_file_flag(session_id: str, device_id: str, file_path: str,
                     severity: str, note: str = ""):
    now = datetime.now().isoformat()
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO file_flags (session_id, device_id, file_path, severity, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id, file_path)
            DO UPDATE SET severity=excluded.severity, note=excluded.note
        """, (session_id, device_id, file_path, severity, note, now))
        conn.commit()


def remove_file_flag(session_id: str, file_path: str):
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM file_flags WHERE session_id=? AND file_path=?",
            (session_id, file_path)
        )
        conn.commit()


def get_file_flags(session_id: str) -> list:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM file_flags WHERE session_id=? ORDER BY created_at DESC",
            (session_id,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def delete_file_flags_for_session(session_id: str, device_id: str):
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM file_flags WHERE session_id=? AND device_id=?",
            (session_id, device_id)
        )
        conn.commit()
