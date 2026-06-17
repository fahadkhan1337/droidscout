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
import xml.etree.ElementTree as ET


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


# ---------------------------------------------------------------------------
# Manual import parsers
# ---------------------------------------------------------------------------

def parse_sms_backup_xml(raw: str) -> list[dict]:
    """Parse SMS Backup & Restore XML exports."""
    results = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return results
    from datetime import datetime, timezone
    for node in root.findall(".//sms"):
        ts_ms = node.attrib.get("date", "")
        try:
            dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = ts_ms
        results.append({
            "id": node.attrib.get("_id", ""),
            "address": node.attrib.get("address", ""),
            "body": node.attrib.get("body", ""),
            "type": SMS_TYPES.get(node.attrib.get("type", ""), node.attrib.get("type", "")),
            "date": dt,
            "read": "Yes" if node.attrib.get("read") == "1" else "No",
            "source": "manual_import",
        })
    return results


def parse_sms_csv(raw: str) -> list[dict]:
    rows = list(csv.DictReader(io.StringIO(raw)))
    result = []
    for i, row in enumerate(rows, 1):
        lower = {k.lower().strip(): v for k, v in row.items() if k}
        result.append({
            "id": lower.get("id") or lower.get("_id") or str(i),
            "address": lower.get("address") or lower.get("number") or lower.get("phone") or "",
            "body": lower.get("body") or lower.get("message") or lower.get("text") or "",
            "type": lower.get("type") or lower.get("direction") or "",
            "date": lower.get("date") or lower.get("timestamp") or lower.get("time") or "",
            "read": lower.get("read", ""),
            "source": "manual_import",
        })
    return result


def parse_calls_csv(raw: str) -> list[dict]:
    rows = list(csv.DictReader(io.StringIO(raw)))
    result = []
    for i, row in enumerate(rows, 1):
        lower = {k.lower().strip(): v for k, v in row.items() if k}
        result.append({
            "id": lower.get("id") or lower.get("_id") or str(i),
            "number": lower.get("number") or lower.get("phone") or lower.get("address") or "",
            "name": lower.get("name") or lower.get("contact") or "",
            "type": lower.get("type") or lower.get("direction") or "",
            "duration": lower.get("duration") or "",
            "date": lower.get("date") or lower.get("timestamp") or lower.get("time") or "",
            "source": "manual_import",
        })
    return result


def parse_contacts_csv(raw: str) -> list[dict]:
    rows = list(csv.DictReader(io.StringIO(raw)))
    result = []
    for i, row in enumerate(rows, 1):
        lower = {k.lower().strip(): v for k, v in row.items() if k}
        result.append({
            "id": lower.get("id") or lower.get("_id") or str(i),
            "name": lower.get("name") or lower.get("display_name") or lower.get("full name") or "Unknown",
            "number": lower.get("number") or lower.get("phone") or lower.get("mobile") or "",
            "type": lower.get("type") or "",
            "source": "manual_import",
        })
    return result


def parse_contacts_vcf(raw: str) -> list[dict]:
    contacts = []
    current = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.upper() == "BEGIN:VCARD":
            current = {}
        elif line.upper() == "END:VCARD":
            if current:
                contacts.append({
                    "id": str(len(contacts) + 1),
                    "name": current.get("name", "Unknown"),
                    "number": current.get("number", ""),
                    "type": "VCF",
                    "source": "manual_import",
                })
        elif line.upper().startswith("FN:"):
            current["name"] = line.split(":", 1)[1]
        elif line.upper().startswith("TEL"):
            current["number"] = line.split(":", 1)[1] if ":" in line else ""
    return contacts
