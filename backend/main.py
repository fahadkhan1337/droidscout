import hashlib
import os
import sys
import glob
import json
import re
import shutil
from datetime import datetime

# Force UTF-8 output on Windows to handle Unicode characters in print statements
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Dict, Any

from utils.adb_helper import ADBHelper
from modules.acquisition import AcquisitionModule
from modules.hashing import HashingModule
from modules.analysis import AnalysisModule
from modules.reporting import ReportingModule
from fastapi.staticfiles import StaticFiles
from database import (
    init_db, create_session, update_session, get_session, get_all_records,
    delete_session, update_case_metadata,
    upsert_file_flag, remove_file_flag, get_file_flags, delete_file_flags_for_session,
    get_all_file_flags,
    acknowledge_flag, unacknowledge_flag, get_acknowledgments, get_all_acknowledgments,
)
from modules.parser import (
    parse_contacts, parse_calls, parse_sms, contacts_to_csv, calls_to_csv, sms_to_csv,
    search_evidence, parse_sms_backup_xml, parse_sms_csv, parse_calls_csv,
    parse_contacts_csv, parse_contacts_vcf,
)
from fastapi.responses import StreamingResponse
import io

app = FastAPI(title="DroidTrace API", version="1.0.0")

# Initialise SQLite database
init_db()

# Mount static frontend
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if not os.path.exists(frontend_dir):
    os.makedirs(frontend_dir)


# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

adb = ADBHelper()

class DeviceInfo(BaseModel):
    id: str
    manufacturer: str
    model: str

class DeviceListResponse(BaseModel):
    devices: List[DeviceInfo]

class AcquireOptions(BaseModel):
    user_storage:    bool = True
    app_media:       bool = True
    metadata_logcat: bool = True
    network_info:    bool = True
    screenshot:      bool = True
    processes:       bool = True
    communication:   bool = True
    case_number:     str  = ""
    investigator:    str  = ""
    notes:           str  = ""

class CaseMetadata(BaseModel):
    case_number:  str = ""
    investigator: str = ""
    notes:        str = ""

class GenericResponse(BaseModel):
    status: str
    message: str

class WirelessAdbRequest(BaseModel):
    host: str
    port: int = 5555

IMPORT_TYPES = {"sms", "calls", "contacts"}

def _safe_device_dir(device_id: str) -> str:
    """Filesystem-safe folder name for ADB serials such as 127.0.0.1:5555."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", device_id).strip("._")
    return safe or "device"

def _session_path(device_id: str, session_id: str) -> str:
    rec = get_session(session_id)
    path = rec.get("output_dir") if rec else os.path.join("output", device_id, session_id)
    return path if os.path.isabs(path) else os.path.join(os.path.dirname(__file__), path)

def _session_evidence_dir(device_id: str, session_id: str) -> str:
    return os.path.join(_session_path(device_id, session_id), "evidence")

def _load_manifest(session_path: str) -> dict:
    path = os.path.join(session_path, "evidence", "acquisition_manifest.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_manifest(session_path: str, manifest: dict):
    path = os.path.join(session_path, "evidence", "acquisition_manifest.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

def _append_file_metadata(session_path: str, rel_path: str, source: str):
    meta_path = os.path.join(session_path, "evidence", "file_metadata.json")
    try:
        with open(meta_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {"generated_at": datetime.now().isoformat(), "files": {}}
    full = os.path.join(session_path, "evidence", rel_path)
    try:
        st = os.stat(full)
        data.setdefault("files", {})[rel_path.replace("\\", "/")] = {
            "source": source,
            "remote_path": "",
            "size_bytes": st.st_size,
            "device_modified_time": "",
            "local_acquired_time": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "metadata_status": "manual_import",
        }
        data["generated_at"] = datetime.now().isoformat()
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

@app.post("/api/adb/start", response_model=GenericResponse)
def start_adb_server():
    success = adb.start_server()
    if success:
        return {"status": "success", "message": "ADB server started successfully."}
    raise HTTPException(status_code=500, detail="Failed to start ADB server.")

@app.post("/api/adb/stop", response_model=GenericResponse)
def stop_adb_server():
    success = adb.kill_server()
    if success:
        return {"status": "success", "message": "ADB server stopped successfully."}
    raise HTTPException(status_code=500, detail="Failed to stop ADB server.")

@app.post("/api/adb/connect", response_model=GenericResponse)
def connect_wireless_adb(body: WirelessAdbRequest):
    host = body.host.strip()
    if not host:
        raise HTTPException(status_code=400, detail="Host/IP is required.")
    if body.port < 1 or body.port > 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535.")
    success, message = adb.connect_tcpip(host, body.port)
    if success:
        return {"status": "success", "message": message or f"Connected to {host}:{body.port}"}
    raise HTTPException(status_code=500, detail=message or f"Failed to connect to {host}:{body.port}.")

@app.post("/api/adb/disconnect", response_model=GenericResponse)
def disconnect_wireless_adb(body: WirelessAdbRequest):
    host = body.host.strip()
    if body.port < 1 or body.port > 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535.")
    success, message = adb.disconnect_tcpip(host, body.port)
    if success:
        return {"status": "success", "message": message or f"Disconnected {host}:{body.port}"}
    raise HTTPException(status_code=500, detail=message or f"Failed to disconnect {host}:{body.port}.")

@app.get("/api/devices", response_model=DeviceListResponse)
def get_devices():
    try:
        devices = adb.get_connected_devices()
        device_list = []
        for d in devices:
            props = ADBHelper(d).get_device_props()
            device_list.append({
                "id": d,
                "manufacturer": props.get("manufacturer", "Unknown").title(),
                "model": props.get("model", "Android Device")
            })
        return {"devices": device_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def run_acquisition_pipeline(session_id: str, device_id: str, output_dir: str, options: dict):
    try:
        def status_cb(msg):
            update_session(session_id, "running", msg)

        update_session(session_id, "running", "Pulling data from device...")

        # Acquisition
        acq = AcquisitionModule(serial=device_id, output_dir=output_dir, status_callback=status_cb)
        manifest = acq.acquire_all(options)

        if not manifest:
            update_session(session_id, "failed", "Acquisition failed or no files to acquire.")
            return

        status_cb("Computing SHA-256 hashes...")

        # Hashing
        HashingModule(output_dir=output_dir, status_callback=status_cb).hash_evidence()

        status_cb("Analyzing acquired evidence...")

        # Analysis
        AnalysisModule(output_dir=output_dir, status_callback=status_cb).analyze()

        status_cb("Generating forensic reports...")

        # Reporting
        rm = ReportingModule(output_dir=output_dir, status_callback=status_cb)
        rm.file_flags = get_file_flags(session_id)
        rm.generate_all()

        device_info = manifest.get("device_info", {})
        update_session(
            session_id,
            "completed",
            "Full pipeline completed successfully.",
            manifest=manifest,
            device_info=device_info,
        )

    except Exception as e:
        update_session(session_id, "failed", f"Pipeline error: {str(e)}")

@app.post("/api/acquire/{device_id}")
def acquire_data(device_id: str, options: AcquireOptions, background_tasks: BackgroundTasks):
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join("output", _safe_device_dir(device_id), session_id)

    create_session(session_id, device_id, output_dir)

    # Save case metadata to DB and to disk so reporting.py can embed it
    update_case_metadata(session_id, options.case_number, options.investigator, options.notes)
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "case_metadata.json"), "w", encoding="utf-8") as f:
        json.dump({
            "case_number":  options.case_number,
            "investigator": options.investigator,
            "notes":        options.notes,
        }, f, indent=2)

    background_tasks.add_task(run_acquisition_pipeline, session_id, device_id, output_dir, options.model_dump())

    return {
        "status": "started",
        "message": "Acquisition started in background.",
        "session_id": session_id,
    }

@app.get("/api/acquire/status/{session_id}")
def get_acquire_status(session_id: str):
    record = get_session(session_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Session not found.")
    return {
        "status":   record["status"],
        "message":  record["message"],
        "manifest": json.loads(record["manifest"]) if record.get("manifest") else None,
    }

@app.get("/api/records")
def get_records():
    """Returns a list of all acquisitions grouped by device ID from SQLite."""
    return {"records": get_all_records()}

@app.delete("/api/records/{device_id}/{session_id}")
def delete_record(device_id: str, session_id: str):
    # Check DB first — that's the source of truth
    record = get_session(session_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found.")

    try:
        # Prefer the stored output_dir; fall back to conventional path
        session_path = record.get("output_dir") or os.path.join("output", device_id, session_id)
        # Make absolute relative to backend dir if not already absolute
        if not os.path.isabs(session_path):
            session_path = os.path.join(os.path.dirname(__file__), session_path)

        if os.path.isdir(session_path):
            shutil.rmtree(session_path)
            parent = os.path.dirname(session_path)
            if os.path.isdir(parent) and not os.listdir(parent):
                os.rmdir(parent)

        delete_session(session_id, device_id)
        delete_file_flags_for_session(session_id, device_id)

        return {"status": "success", "message": "Record deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete record: {str(e)}")

@app.patch("/api/records/{device_id}/{session_id}/metadata")
def patch_case_metadata(device_id: str, session_id: str, meta: CaseMetadata):
    """Update case number, investigator and notes for an existing session."""
    record = get_session(session_id)
    if not record:
        raise HTTPException(status_code=404, detail="Session not found.")
    update_case_metadata(session_id, meta.case_number, meta.investigator, meta.notes)
    return {"status": "ok", "message": "Case metadata updated."}

@app.get("/api/records/{device_id}/{session_id}/summary")
def get_session_summary(device_id: str, session_id: str):
    """Return key stats from analysis.json for the completion modal."""
    analysis_path = os.path.join(_session_path(device_id, session_id), "reports", "analysis.json")
    if not os.path.exists(analysis_path):
        raise HTTPException(status_code=404, detail="Analysis not ready yet.")
    with open(analysis_path, encoding="utf-8") as f:
        analysis = json.load(f)
    summary = analysis.get("summary", {})
    return {
        "total_files":  summary.get("total_files", 0),
        "total_size_mb": summary.get("total_size_mb", 0),
        "total_flags":  len(analysis.get("forensic_flags", [])),
    }

@app.get("/api/records/{device_id}/{session_id}/log")
def get_acquisition_log(device_id: str, session_id: str):
    """Return the acquisition manifest log entries for inline viewing."""
    manifest_path = os.path.join(_session_evidence_dir(device_id, session_id), "acquisition_manifest.json")
    if not os.path.exists(manifest_path):
        raise HTTPException(status_code=404, detail="Manifest not found.")
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    return {
        "session_id":        manifest.get("session_id"),
        "acquisition_time":  manifest.get("acquisition_time"),
        "duration_seconds":  manifest.get("duration_seconds"),
        "device_info":       manifest.get("device_info", {}),
        "log":               manifest.get("log", []),
        "storage_summary":   [{"path": s.get("remote_path"), "status": s.get("status"), "files": s.get("files_pulled", 0)} for s in manifest.get("storage", [])],
        "app_summary":       [{"app": s.get("app"), "status": s.get("status"), "files": s.get("files_pulled", 0)} for s in manifest.get("apps", [])],
    }

def _read_evidence_file(device_id: str, session_id: str, filename: str) -> str:
    path = os.path.join(_session_evidence_dir(device_id, session_id), filename)
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()

@app.get("/api/records/{device_id}/{session_id}/contacts")
def get_contacts(device_id: str, session_id: str):
    raw = _read_evidence_file(device_id, session_id, "contacts.txt")
    imported = _read_evidence_file(device_id, session_id, "contacts_imported.txt")
    if imported:
        try:
            return {"contacts": json.loads(imported), "raw_available": bool(raw), "source": "manual_import"}
        except Exception:
            pass
    if not raw:
        raise HTTPException(status_code=404, detail="Contacts file not found.")
    return {"contacts": parse_contacts(raw), "raw_available": True, "source": "adb"}

@app.get("/api/records/{device_id}/{session_id}/contacts/csv")
def download_contacts_csv(device_id: str, session_id: str):
    raw = _read_evidence_file(device_id, session_id, "contacts.txt")
    if not raw:
        raise HTTPException(status_code=404, detail="Contacts file not found.")
    csv_data = contacts_to_csv(parse_contacts(raw))
    return StreamingResponse(io.StringIO(csv_data), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=contacts_{session_id}.csv"})

@app.get("/api/records/{device_id}/{session_id}/calls")
def get_calls(device_id: str, session_id: str):
    raw = _read_evidence_file(device_id, session_id, "call_logs.txt")
    imported = _read_evidence_file(device_id, session_id, "call_logs_imported.txt")
    if imported:
        try:
            return {"calls": json.loads(imported), "source": "manual_import"}
        except Exception:
            pass
    if not raw:
        raise HTTPException(status_code=404, detail="Call logs file not found.")
    return {"calls": parse_calls(raw), "source": "adb"}

@app.get("/api/records/{device_id}/{session_id}/calls/csv")
def download_calls_csv(device_id: str, session_id: str):
    raw = _read_evidence_file(device_id, session_id, "call_logs.txt")
    if not raw:
        raise HTTPException(status_code=404, detail="Call logs file not found.")
    csv_data = calls_to_csv(parse_calls(raw))
    return StreamingResponse(io.StringIO(csv_data), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=calls_{session_id}.csv"})

@app.get("/api/records/{device_id}/{session_id}/sms")
def get_sms_data(device_id: str, session_id: str):
    raw = _read_evidence_file(device_id, session_id, "sms.txt")
    imported = _read_evidence_file(device_id, session_id, "sms_imported.txt")
    if imported:
        try:
            return {"sms": json.loads(imported), "source": "manual_import"}
        except Exception:
            pass
    if not raw:
        raise HTTPException(status_code=404, detail="SMS file not found.")
    return {"sms": parse_sms(raw), "source": "adb"}

@app.get("/api/records/{device_id}/{session_id}/sms/csv")
def download_sms_csv(device_id: str, session_id: str):
    raw = _read_evidence_file(device_id, session_id, "sms.txt")
    if not raw:
        raise HTTPException(status_code=404, detail="SMS file not found.")
    csv_data = sms_to_csv(parse_sms(raw))
    return StreamingResponse(io.StringIO(csv_data), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sms_{session_id}.csv"})

@app.post("/api/records/{device_id}/{session_id}/imports/{import_type}")
async def import_communication_file(
    device_id: str,
    session_id: str,
    import_type: str,
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
):
    """Import SMS/calls/contacts evidence when Android blocks direct acquisition."""
    if import_type not in IMPORT_TYPES:
        raise HTTPException(status_code=400, detail="import_type must be sms, calls, or contacts.")
    session_path = _session_path(device_id, session_id)
    evidence_dir = os.path.join(session_path, "evidence")
    if not os.path.isdir(evidence_dir):
        raise HTTPException(status_code=404, detail="Evidence folder not found.")

    raw_bytes = await file.read()
    raw_text = raw_bytes.decode("utf-8", errors="replace")
    filename = os.path.basename(file.filename or f"{import_type}_import.txt")
    imports_dir = os.path.join(evidence_dir, "imports", import_type)
    os.makedirs(imports_dir, exist_ok=True)
    raw_path = os.path.join(imports_dir, filename)
    with open(raw_path, "wb") as f:
        f.write(raw_bytes)

    ext = os.path.splitext(filename)[1].lower()
    if import_type == "sms":
        parsed = parse_sms_backup_xml(raw_text) if ext == ".xml" else parse_sms_csv(raw_text)
        normalized_name = "sms_imported.json"
        text_name = "sms_imported.txt"
    elif import_type == "calls":
        parsed = parse_calls_csv(raw_text)
        normalized_name = "call_logs_imported.json"
        text_name = "call_logs_imported.txt"
    else:
        parsed = parse_contacts_vcf(raw_text) if ext == ".vcf" else parse_contacts_csv(raw_text)
        normalized_name = "contacts_imported.json"
        text_name = "contacts_imported.txt"

    normalized_path = os.path.join(imports_dir, normalized_name)
    with open(normalized_path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2)
    text_path = os.path.join(evidence_dir, text_name)
    with open(text_path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2)

    raw_rel = os.path.relpath(raw_path, evidence_dir).replace("\\", "/")
    norm_rel = os.path.relpath(normalized_path, evidence_dir).replace("\\", "/")
    text_rel = os.path.relpath(text_path, evidence_dir).replace("\\", "/")
    for rel in (raw_rel, norm_rel, text_rel):
        _append_file_metadata(session_path, rel, "manual_import")

    manifest = _load_manifest(session_path)
    manifest.setdefault("communication", {})
    manifest["communication"][import_type] = {
        "status": "collected" if parsed else "empty",
        "rows": len(parsed),
        "file": text_name,
        "raw_import": raw_rel,
        "normalized_import": norm_rel,
        "source": "manual_import",
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "imported_at": datetime.now().isoformat(),
    }
    manifest.setdefault("evidence_sources", [])
    if "manual_import" not in manifest["evidence_sources"]:
        manifest["evidence_sources"].append("manual_import")
    _save_manifest(session_path, manifest)

    if background_tasks is not None:
        def run_reanalysis():
            try:
                HashingModule(output_dir=session_path).hash_evidence()
                AnalysisModule(output_dir=session_path).analyze()
                rm = ReportingModule(output_dir=session_path)
                rm.file_flags = get_file_flags(session_id)
                rm.generate_all()
            except Exception as e:
                print(f"[!] Import reanalysis failed: {e}")
        background_tasks.add_task(run_reanalysis)

    return {
        "status": "imported",
        "type": import_type,
        "rows": len(parsed),
        "raw_file": raw_rel,
        "normalized_file": norm_rel,
        "message": "Import saved as evidence and reanalysis queued.",
    }

@app.get("/api/records/{device_id}/{session_id}/search")
def search_session(device_id: str, session_id: str, q: str = ""):
    if not q.strip():
        raise HTTPException(status_code=400, detail="Query parameter 'q' is required.")
    evidence_dir = _session_evidence_dir(device_id, session_id)
    if not os.path.exists(evidence_dir):
        raise HTTPException(status_code=404, detail="Evidence directory not found.")
    results = search_evidence(evidence_dir, q.strip())
    return {"query": q, "total": len(results), "results": results}

@app.get("/api/stats")
def get_stats():
    """Global statistics across all sessions."""
    records = get_all_records()
    total_sessions = sum(len(s) for s in records.values())
    total_devices  = len(records)
    completed      = sum(1 for ss in records.values() for s in ss if s.get("status") == "completed")
    failed         = sum(1 for ss in records.values() for s in ss if s.get("status") == "failed")

    total_files = 0
    total_flags = 0
    total_size_mb = 0.0

    for device_id, sessions in records.items():
        for s in sessions:
            session_path = _session_path(device_id, s["session_id"])
            analysis_path = os.path.join(session_path, "reports", "analysis.json")
            if os.path.exists(analysis_path):
                try:
                    with open(analysis_path, encoding="utf-8") as f:
                        analysis = json.load(f)
                    summary = analysis.get("summary", {})
                    total_files   += summary.get("total_files", 0)
                    total_size_mb += summary.get("total_size_mb", 0)
                    total_flags   += len(analysis.get("forensic_flags", []))
                except Exception:
                    pass

    return {
        "total_devices":   total_devices,
        "total_sessions":  total_sessions,
        "completed":       completed,
        "failed":          failed,
        "total_files":     total_files,
        "total_size_mb":   round(total_size_mb, 2),
        "total_flags":     total_flags,
    }

def _load_session_analysis(device_id: str, session_id: str) -> dict:
    """Load analysis.json for a session, return {} if missing."""
    p = os.path.join(_session_path(device_id, session_id), "reports", "analysis.json")
    if not os.path.exists(p):
        # Try path from DB
        rec = get_session(session_id)
        if rec and rec.get("output_dir"):
            p2 = os.path.join(rec["output_dir"], "reports", "analysis.json")
            if os.path.exists(p2):
                p = p2
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

@app.get("/timeline/{device_id}")
def timeline_page(device_id: str):
    page = os.path.join(frontend_dir, "timeline.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="Timeline page not found.")
    return FileResponse(page, media_type="text/html")

@app.get("/api/timeline/{device_id}")
def get_device_timeline(device_id: str):
    """All sessions for a device with summary stats for the timeline."""
    records = get_all_records()
    sessions = records.get(device_id, [])
    if not sessions:
        raise HTTPException(status_code=404, detail="Device not found.")
    result = []
    for s in sorted(sessions, key=lambda x: x.get("timestamp", ""), reverse=False):
        analysis = _load_session_analysis(device_id, s["session_id"])
        summary  = analysis.get("summary", {})
        flags    = analysis.get("forensic_flags", [])
        flag_by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for fl in flags:
            sev = fl.get("severity", "LOW")
            flag_by_sev[sev] = flag_by_sev.get(sev, 0) + 1
        result.append({
            "session_id":   s["session_id"],
            "status":       s.get("status", ""),
            "timestamp":    s.get("timestamp", ""),
            "case_number":  s.get("case_number", ""),
            "investigator": s.get("investigator", ""),
            "notes":        s.get("notes", ""),
            "total_files":  summary.get("total_files", 0),
            "total_size_mb":round(summary.get("total_size_mb", 0), 2),
            "total_flags":  len(flags),
            "flags_by_sev": flag_by_sev,
            "categories":   {k: v.get("count", 0) for k, v in analysis.get("file_categories", {}).items()},
        })
    return {"device_id": device_id, "sessions": result}

@app.get("/api/timeline/{device_id}/compare")
def compare_sessions(device_id: str, s1: str, s2: str):
    """Compare two sessions — files added/removed, flag changes."""
    def load(sid):
        analysis = _load_session_analysis(device_id, sid)
        manifest_p = None
        rec = get_session(sid)
        if rec and rec.get("output_dir"):
            mp = os.path.join(rec["output_dir"], "evidence", "acquisition_manifest.json")
            if os.path.exists(mp):
                try:
                    with open(mp, encoding="utf-8") as f:
                        manifest_p = json.load(f)
                except: pass
        return analysis, manifest_p

    a1, m1 = load(s1)
    a2, m2 = load(s2)

    def files_set(analysis):
        cats = analysis.get("file_categories", {})
        out = {}
        for cat, data in cats.items():
            out[cat] = data.get("count", 0)
        return out

    cats1, cats2 = files_set(a1), files_set(a2)
    all_cats = set(cats1) | set(cats2)
    cat_diff = {c: {"before": cats1.get(c, 0), "after": cats2.get(c, 0)} for c in sorted(all_cats)}

    flags1 = {(f.get("type",""), f.get("file","")): f for f in a1.get("forensic_flags", [])}
    flags2 = {(f.get("type",""), f.get("file","")): f for f in a2.get("forensic_flags", [])}
    new_flags     = [v for k, v in flags2.items() if k not in flags1]
    resolved_flags= [v for k, v in flags1.items() if k not in flags2]

    s1_sum = a1.get("summary", {})
    s2_sum = a2.get("summary", {})
    return {
        "session_1": s1, "session_2": s2,
        "summary_diff": {
            "files":   {"before": s1_sum.get("total_files", 0),   "after": s2_sum.get("total_files", 0)},
            "size_mb": {"before": round(s1_sum.get("total_size_mb", 0), 2),
                        "after":  round(s2_sum.get("total_size_mb", 0), 2)},
            "flags":   {"before": len(flags1), "after": len(flags2)},
        },
        "category_diff":   cat_diff,
        "new_flags":       new_flags[:30],
        "resolved_flags":  resolved_flags[:30],
    }

MEDIA_TYPES = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".mp4": "video/mp4", ".mkv": "video/x-matroska", ".avi": "video/x-msvideo",
    ".mov": "video/quicktime", ".3gp": "video/3gpp", ".webm": "video/webm",
    ".mp3": "audio/mpeg", ".aac": "audio/aac", ".wav": "audio/wav",
    ".ogg": "audio/ogg", ".m4a": "audio/mp4", ".opus": "audio/opus",
    ".flac": "audio/flac", ".amr": "audio/amr",
    ".pdf": "application/pdf", ".txt": "text/plain",
}

def _safe_path(device_id: str, session_id: str, rel_path: str = "") -> str:
    """Resolve and validate path stays within session output directory."""
    base = os.path.abspath(_session_evidence_dir(device_id, session_id))
    full = os.path.abspath(os.path.join(base, rel_path.lstrip("/\\"))) if rel_path else base
    if not full.startswith(base):
        raise HTTPException(status_code=403, detail="Access denied.")
    return full

@app.get("/api/explorer/{device_id}/{session_id}")
def list_files(device_id: str, session_id: str, path: str = ""):
    """List directory contents for the file explorer."""
    full = _safe_path(device_id, session_id, path)
    if not os.path.exists(full):
        raise HTTPException(status_code=404, detail="Path not found.")

    flags = {f["file_path"]: f for f in get_file_flags(session_id)}
    items = []

    if os.path.isdir(full):
        for name in sorted(os.listdir(full)):
            child = os.path.join(full, name)
            rel = os.path.relpath(child, _safe_path(device_id, session_id)).replace("\\", "/")
            is_dir = os.path.isdir(child)
            ext = os.path.splitext(name)[1].lower()
            size = 0
            if not is_dir:
                try: size = os.path.getsize(child)
                except: pass
            items.append({
                "name":     name,
                "path":     rel,
                "is_dir":   is_dir,
                "ext":      ext,
                "size":     size,
                "size_mb":  round(size / 1_048_576, 2),
                "media_type": MEDIA_TYPES.get(ext, ""),
                "flag":     flags.get(rel),
            })
    return {"path": path, "items": items}

@app.get("/api/explorer/{device_id}/{session_id}/serve")
def serve_file(device_id: str, session_id: str, path: str = ""):
    """Serve a file for preview or playback in the browser."""
    full = _safe_path(device_id, session_id, path)
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail="File not found.")
    ext = os.path.splitext(full)[1].lower()
    media_type = MEDIA_TYPES.get(ext, "application/octet-stream")
    return FileResponse(full, media_type=media_type)

@app.get("/api/explorer/{device_id}/{session_id}/download")
def download_file(device_id: str, session_id: str, path: str = ""):
    """Download a single file."""
    full = _safe_path(device_id, session_id, path)
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail="File not found.")
    return FileResponse(full, filename=os.path.basename(full), media_type="application/octet-stream")

class FileFlagRequest(BaseModel):
    file_path: str
    severity:  str = "INFO"
    note:      str = ""

@app.post("/api/explorer/{device_id}/{session_id}/flag")
def set_file_flag(device_id: str, session_id: str, body: FileFlagRequest):
    upsert_file_flag(session_id, device_id, body.file_path, body.severity, body.note)
    return {"status": "ok"}

@app.delete("/api/explorer/{device_id}/{session_id}/flag")
def clear_file_flag(device_id: str, session_id: str, path: str):
    remove_file_flag(session_id, path)
    return {"status": "ok"}

@app.get("/api/explorer/{device_id}/{session_id}/flags")
def list_file_flags(device_id: str, session_id: str):
    return {"flags": get_file_flags(session_id)}

# ── Forensic flag acknowledgments ────────────────────────────────────────────

class AckBody(BaseModel):
    flag_key:        str
    acknowledged_by: str = ""
    note:            str = ""

@app.post("/api/flags/{device_id}/{session_id}/acknowledge")
def ack_flag(device_id: str, session_id: str, body: AckBody):
    acknowledge_flag(session_id, device_id, body.flag_key,
                     body.acknowledged_by, body.note)
    return {"status": "ok"}

@app.delete("/api/flags/{device_id}/{session_id}/acknowledge")
def unack_flag(device_id: str, session_id: str, flag_key: str):
    unacknowledge_flag(session_id, flag_key)
    return {"status": "ok"}

@app.get("/api/flags/{device_id}/{session_id}/acknowledgments")
def list_acks(device_id: str, session_id: str):
    acks = get_acknowledgments(session_id)
    return {"acknowledgments": {a["flag_key"]: a for a in acks}}

# ── Centralized flags view ────────────────────────────────────────────────────

@app.get("/flags")
def flags_page():
    page = os.path.join(frontend_dir, "flags.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="Flags page not found.")
    return FileResponse(page, media_type="text/html")

@app.get("/api/flags/all")
def all_flags_view():
    """All forensic + investigator flags across every session, with ack status."""
    records = get_all_records()
    all_acks = {(a["session_id"], a["flag_key"]): a for a in get_all_acknowledgments()}
    all_iflags = get_all_file_flags()

    result = []
    for device_id, sessions in records.items():
        for s in sessions:
            sid = s["session_id"]
            analysis = _load_session_analysis(device_id, sid)
            forensic_flags = analysis.get("forensic_flags", [])
            for fl in forensic_flags:
                key = fl.get("type", "") + "::" + (fl.get("file") or "")
                ack = all_acks.get((sid, key))
                result.append({
                    "kind":          "forensic",
                    "device_id":     device_id,
                    "session_id":    sid,
                    "timestamp":     s.get("timestamp", ""),
                    "case_number":   s.get("case_number", ""),
                    "severity":      fl.get("severity", "LOW"),
                    "flag_type":     fl.get("type", ""),
                    "description":   fl.get("description", ""),
                    "file":          fl.get("file"),
                    "flag_key":      key,
                    "acknowledged":  bool(ack),
                    "ack_by":        ack["acknowledged_by"] if ack else None,
                    "ack_note":      ack["note"] if ack else None,
                    "ack_at":        ack["created_at"] if ack else None,
                })

    for f in all_iflags:
        result.append({
            "kind":        "investigator",
            "device_id":   f["device_id"],
            "session_id":  f["session_id"],
            "timestamp":   f["created_at"],
            "case_number": "",
            "severity":    f["severity"],
            "flag_type":   "INVESTIGATOR_FLAG",
            "description": f.get("note") or f["file_path"].split("/")[-1],
            "file":        f["file_path"],
            "flag_key":    None,
            "acknowledged": False,
            "ack_by": None, "ack_note": None, "ack_at": None,
        })

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    result.sort(key=lambda x: (sev_rank.get(x.get("severity", "LOW"), 9), x["timestamp"]))
    return {"flags": result}

@app.post("/api/explorer/{device_id}/{session_id}/regenerate-report")
def regenerate_report_with_flags(device_id: str, session_id: str, background_tasks: BackgroundTasks):
    """Re-generate the HTML report to bake in the latest investigator file flags."""
    session_path = _session_path(device_id, session_id)
    if not os.path.exists(session_path):
        raise HTTPException(status_code=404, detail="Session not found.")

    def _regen():
        try:
            rm = ReportingModule(output_dir=session_path)
            rm.file_flags = get_file_flags(session_id)
            rm.load_data()
            rm.generate_html()
        except Exception as e:
            print(f"[!] Report regen failed: {e}")

    background_tasks.add_task(_regen)
    return {"status": "started", "message": "Report regeneration started."}

@app.post("/api/reanalyze/{device_id}/{session_id}")
def reanalyze_session(device_id: str, session_id: str, background_tasks: BackgroundTasks):
    """Re-run analysis + reporting on already-acquired evidence."""
    session_path = _session_path(device_id, session_id)
    evidence_path = _session_evidence_dir(device_id, session_id)
    if not os.path.exists(evidence_path):
        raise HTTPException(status_code=404, detail="Evidence folder not found. Run acquisition first.")

    def run_reanalysis():
        try:
            update_session(session_id, "running", "Re-analyzing evidence...")
            AnalysisModule(output_dir=session_path).analyze()
            update_session(session_id, "running", "Regenerating reports...")
            rm = ReportingModule(output_dir=session_path)
            rm.file_flags = get_file_flags(session_id)
            rm.generate_all()
            update_session(session_id, "completed", "Re-analysis complete.")
        except Exception as e:
            update_session(session_id, "failed", f"Re-analysis error: {str(e)}")

    background_tasks.add_task(run_reanalysis)
    return {"status": "started", "message": "Re-analysis started in background.", "session_id": session_id}

@app.get("/api/reports/verify/{device_id}/{session_id}")
def verify_integrity(device_id: str, session_id: str):
    """Re-hash all evidence files and compare against stored hash manifest."""
    session_path = _session_path(device_id, session_id)
    if not os.path.exists(session_path):
        raise HTTPException(status_code=404, detail="Session not found.")
    try:
        hasher = HashingModule(output_dir=session_path)
        results = hasher.verify_integrity()
        if not results:
            raise HTTPException(status_code=404, detail="Hash manifest not found. Run acquisition first.")
        return {
            "status": "ok",
            "passed":  len(results.get("passed", [])),
            "failed":  len(results.get("failed", [])),
            "missing": len(results.get("missing", [])),
            "violations": results.get("failed", []),
            "missing_files": results.get("missing", []),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/view/{device_id}/{session_id}")
def view_report(device_id: str, session_id: str):
    """Serve the HTML dashboard directly in the browser."""
    session_path = _session_path(device_id, session_id)
    dashboard = os.path.join(session_path, "reports", "dashboard.html")
    if not os.path.exists(dashboard):
        raise HTTPException(status_code=404, detail="Dashboard not found. Acquisition may still be running or failed.")
    return FileResponse(path=dashboard, media_type="text/html")

@app.get("/api/reports/download/{device_id}/{session_id}")
def download_report(device_id: str, session_id: str):
    output_dir = "output"
    session_path = _session_path(device_id, session_id)
    if not os.path.exists(session_path) or not os.path.isdir(session_path):
        raise HTTPException(status_code=404, detail="Record not found.")
        
    zip_filename = f"{_safe_device_dir(device_id)}_{session_id}"
    zip_path = os.path.join(output_dir, zip_filename)
    
    try:
        shutil.make_archive(zip_path, 'zip', session_path)
        return FileResponse(path=zip_path + ".zip", filename=zip_filename + ".zip", media_type="application/zip")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/explorer/{device_id}/{session_id}")
def explorer_page(device_id: str, session_id: str):
    """Serve the standalone file explorer page."""
    page = os.path.join(frontend_dir, "explorer.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="Explorer page not found.")
    return FileResponse(page, media_type="text/html")

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"}
VIDEO_EXTS = {".mp4", ".mkv", ".avi", ".mov", ".3gp", ".webm"}
AUDIO_EXTS = {".mp3", ".aac", ".wav", ".ogg", ".m4a", ".opus", ".flac", ".amr"}
MEDIA_EXTS = IMAGE_EXTS | VIDEO_EXTS | AUDIO_EXTS

APP_PATHS = {
    "whatsapp":  ["whatsapp"],
    "telegram":  ["telegram"],
    "instagram": ["instagram"],
    "signal":    ["signal", "thoughtcrime"],
    "snapchat":  ["snapchat", "com.snap"],
    "tiktok":    ["tiktok", "com.zhiliaoapp"],
    "facebook":  ["facebook", "com.facebook"],
}

@app.get("/api/explorer/{device_id}/{session_id}/media")
def list_media_files(device_id: str, session_id: str, kind: str = "all", app: str = ""):
    """Recursively walk evidence directory and return all media files."""
    base = os.path.abspath(_session_evidence_dir(device_id, session_id))
    if not os.path.isdir(base):
        return {"files": []}
    flags = {f["file_path"]: f for f in get_file_flags(session_id)}
    app_keywords = [kw.lower() for kw in APP_PATHS.get(app.lower(), [])] if app else []
    result = []
    for root, dirs, files in os.walk(base):
        dirs[:] = sorted(dirs)
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if ext not in MEDIA_EXTS:
                continue
            if kind == "images" and ext not in IMAGE_EXTS: continue
            if kind == "videos" and ext not in VIDEO_EXTS: continue
            if kind == "audio"  and ext not in AUDIO_EXTS: continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, base).replace("\\", "/")
            rel_lower = rel.lower()
            if app_keywords and not any(kw in rel_lower for kw in app_keywords):
                continue
            try: size = os.path.getsize(full)
            except: size = 0
            cat = "image" if ext in IMAGE_EXTS else ("video" if ext in VIDEO_EXTS else "audio")
            result.append({
                "name": name, "path": rel, "ext": ext, "size": size,
                "media_type": MEDIA_TYPES.get(ext, ""),
                "category": cat,
                "flag": flags.get(rel),
            })
    return {"files": result, "total": len(result)}

@app.get("/api/explorer/{device_id}/{session_id}/allfiles")
def list_all_files(device_id: str, session_id: str, sort: str = "size", limit: int = 500):
    """Return all files in evidence dir sorted by size (desc) or modified time (desc)."""
    base = os.path.abspath(_session_evidence_dir(device_id, session_id))
    if not os.path.isdir(base):
        return {"files": []}
    flags = {f["file_path"]: f for f in get_file_flags(session_id)}
    result = []
    for root, _, files in os.walk(base):
        for name in files:
            full = os.path.join(root, name)
            rel  = os.path.relpath(full, base).replace("\\", "/")
            try:
                st   = os.stat(full)
                size = st.st_size
                mtime = st.st_mtime
            except:
                size, mtime = 0, 0
            ext = os.path.splitext(name)[1].lower()
            result.append({
                "name": name,
                "path": rel,
                "ext":  ext,
                "size": size,
                "size_mb": round(size / 1_048_576, 3),
                "mtime": mtime,
                "modified": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M") if mtime else "",
                "media_type": MEDIA_TYPES.get(ext, ""),
                "flag": flags.get(rel),
            })
    if sort == "recent":
        result.sort(key=lambda x: x["mtime"], reverse=True)
    else:
        result.sort(key=lambda x: x["size"], reverse=True)
    return {"files": result[:limit], "total": len(result), "sort": sort}

@app.get("/api/explorer/{device_id}/{session_id}/apps")
def list_app_counts(device_id: str, session_id: str):
    """Return per-app media file counts for the gallery filter bar."""
    base = os.path.abspath(_session_evidence_dir(device_id, session_id))
    if not os.path.isdir(base):
        return {"apps": {}}
    counts = {}
    for root, _, files in os.walk(base):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext not in MEDIA_EXTS:
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, base).replace("\\", "/").lower()
            for app_key, keywords in APP_PATHS.items():
                if any(kw in rel for kw in keywords):
                    counts[app_key] = counts.get(app_key, 0) + 1
                    break
    return {"apps": counts}

app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="localhost", port=8000, reload=True)

