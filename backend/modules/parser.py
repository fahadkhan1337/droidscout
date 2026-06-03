"""
parser.py — DroidScout
Parses raw ADB content query output into structured dicts and CSV files.

ADB content query output format:
    Row: 0 _id=1, display_name=John Doe, number=+923001234567, type=2
    Row: 1 _id=2, ...
"""

import csv
import io
import re


# ---------------------------------------------------------------------------
# Core row parser
# ---------------------------------------------------------------------------

def _parse_adb_rows(raw: str) -> list[dict]:
    """Parse ADB 'content query' output into a list of dicts."""
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("Row:"):
            continue
        # Strip leading "Row: N "
        body = re.sub(r"^Row:\s*\d+\s*", "", line)
        entry = {}
        # Split on ", key=" boundaries (handles commas inside values)
        parts = re.split(r",\s*(?=\w+=)", body)
        for part in parts:
            if "=" in part:
                k, _, v = part.partition("=")
                entry[k.strip()] = v.strip()
        if entry:
            rows.append(entry)
    return rows


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------

def parse_contacts(raw: str) -> list[dict]:
    rows = _parse_adb_rows(raw)
    results = []
    for r in rows:
        results.append({
            "id":     r.get("_id", ""),
            "name":   r.get("display_name", "Unknown"),
            "number": r.get("number", ""),
            "type":   _contact_type(r.get("type", "")),
        })
    return results


def contacts_to_csv(contacts: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["id", "name", "number", "type"])
    w.writeheader()
    w.writerows(contacts)
    return buf.getvalue()


def _contact_type(t: str) -> str:
    return {"1": "Home", "2": "Mobile", "3": "Work"}.get(str(t), t or "Unknown")


# ---------------------------------------------------------------------------
# Call logs
# ---------------------------------------------------------------------------

CALL_TYPES = {"1": "Incoming", "2": "Outgoing", "3": "Missed",
              "4": "Voicemail", "5": "Rejected", "6": "Blocked"}

def parse_calls(raw: str) -> list[dict]:
    rows = _parse_adb_rows(raw)
    results = []
    for r in rows:
        ts_ms = r.get("date", "")
        from datetime import datetime, timezone
        try:
            dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = ts_ms

        dur_s = r.get("duration", "")
        try:
            mins, secs = divmod(int(dur_s), 60)
            duration_fmt = f"{mins}m {secs}s"
        except Exception:
            duration_fmt = dur_s

        results.append({
            "id":        r.get("_id", ""),
            "number":    r.get("number", ""),
            "name":      r.get("name", ""),
            "type":      CALL_TYPES.get(r.get("type", ""), r.get("type", "")),
            "duration":  duration_fmt,
            "date":      dt,
        })
    return results


def calls_to_csv(calls: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["id", "number", "name", "type", "duration", "date"])
    w.writeheader()
    w.writerows(calls)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------

SMS_TYPES = {"1": "Received", "2": "Sent", "3": "Draft",
             "4": "Outbox", "5": "Failed", "6": "Queued"}

def parse_sms(raw: str) -> list[dict]:
    rows = _parse_adb_rows(raw)
    results = []
    for r in rows:
        ts_ms = r.get("date", "")
        from datetime import datetime, timezone
        try:
            dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = ts_ms

        results.append({
            "id":      r.get("_id", ""),
            "address": r.get("address", ""),
            "body":    r.get("body", ""),
            "type":    SMS_TYPES.get(r.get("type", ""), r.get("type", "")),
            "date":    dt,
            "read":    "Yes" if r.get("read") == "1" else "No",
        })
    return results


def sms_to_csv(sms: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["id", "address", "type", "date", "read", "body"])
    w.writeheader()
    w.writerows(sms)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Keyword search across all evidence text files
# ---------------------------------------------------------------------------

from pathlib import Path

SEARCHABLE_FILES = [
    "contacts.txt", "sms.txt", "call_logs.txt", "logcat.txt",
    "installed_packages.txt", "battery_info.txt", "network_info.txt",
    "wifi_info.txt", "running_processes.txt",
]

def search_evidence(evidence_dir: str, query: str, max_results: int = 200) -> list[dict]:
    """
    Full-text search across all evidence text files.
    Returns list of {file, line_number, line} matches.
    """
    if not query:
        return []
    q = query.lower()
    results = []
    root = Path(evidence_dir)

    for fname in SEARCHABLE_FILES:
        fpath = root / fname
        if not fpath.exists():
            continue
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
            for i, line in enumerate(lines, 1):
                if q in line.lower():
                    results.append({
                        "file":        fname,
                        "line_number": i,
                        "line":        line.strip()[:300],
                    })
                    if len(results) >= max_results:
                        return results
        except Exception:
            continue
    return results
