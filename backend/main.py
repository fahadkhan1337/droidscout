import os
import glob
import json
import shutil
from datetime import datetime
from fastapi import FastAPI, HTTPException, BackgroundTasks
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

app = FastAPI(title="DroidScout API", version="1.0.0")

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

# Global state for background acquisitions
# Format: { session_id: { "status": "running"|"completed"|"failed", "message": "...", "manifest": dict|None } }
active_tasks = {}

class DeviceInfo(BaseModel):
    id: str
    manufacturer: str
    model: str

class DeviceListResponse(BaseModel):
    devices: List[DeviceInfo]

class AcquireOptions(BaseModel):
    user_storage: bool = True
    app_media: bool = True
    metadata_logcat: bool = True

class GenericResponse(BaseModel):
    status: str
    message: str

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
            if session_id in active_tasks:
                active_tasks[session_id]["message"] = msg

        active_tasks[session_id] = {"status": "running", "message": "Pulling data from device...", "manifest": None}
        
        # Acquisition
        acq = AcquisitionModule(serial=device_id, output_dir=output_dir, status_callback=status_cb)
        manifest = acq.acquire_all(options)
        
        if not manifest:
            active_tasks[session_id] = {"status": "failed", "message": "Acquisition failed or no files to acquire.", "manifest": None}
            return
            
        status_cb("Computing SHA-256 hashes...")
        
        # Hashing
        hasher = HashingModule(output_dir=output_dir, status_callback=status_cb)
        hasher.hash_evidence()
        
        status_cb("Analyzing acquired evidence...")
        
        # Analysis
        AnalysisModule(output_dir=output_dir, status_callback=status_cb).analyze()
        
        status_cb("Generating forensic reports...")
        
        # Reporting
        ReportingModule(output_dir=output_dir, status_callback=status_cb).generate_all()
        
        active_tasks[session_id] = {
            "status": "completed",
            "message": "Full pipeline completed successfully.",
            "manifest": manifest
        }
    except Exception as e:
        active_tasks[session_id] = {
            "status": "failed",
            "message": f"Pipeline error: {str(e)}",
            "manifest": None
        }

@app.post("/api/acquire/{device_id}")
def acquire_data(device_id: str, options: AcquireOptions, background_tasks: BackgroundTasks):
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join("output", device_id, session_id)
    
    # Initialize state
    active_tasks[session_id] = {"status": "starting", "message": "Initializing...", "manifest": None}
    
    # Start background task
    background_tasks.add_task(run_acquisition_pipeline, session_id, device_id, output_dir, options.model_dump())
    
    return {
        "status": "started",
        "message": "Acquisition started in background.",
        "session_id": session_id
    }

@app.get("/api/acquire/status/{session_id}")
def get_acquire_status(session_id: str):
    if session_id not in active_tasks:
        raise HTTPException(status_code=404, detail="Session not found.")
    return active_tasks[session_id]

@app.get("/api/records")
def get_records():
    """Returns a list of all acquisitions grouped by device ID."""
    records = {}
    output_dir = "output"
    
    if not os.path.exists(output_dir):
        return {"records": records}
        
    for device_id in os.listdir(output_dir):
        device_path = os.path.join(output_dir, device_id)
        if os.path.isdir(device_path):
            records[device_id] = []
            for session_id in os.listdir(device_path):
                session_path = os.path.join(device_path, session_id)
                if os.path.isdir(session_path):
                    # Try to read manifest for summary
                    manifest_path = os.path.join(session_path, "evidence", "acquisition_manifest.json")
                    summary = {"session_id": session_id, "timestamp": None, "device_info": None, "path": session_path}
                    if os.path.exists(manifest_path):
                        try:
                            with open(manifest_path, 'r', encoding='utf-8') as f:
                                manifest = json.load(f)
                                summary["timestamp"] = manifest.get("acquisition_time")
                                summary["device_info"] = manifest.get("device_info", {})
                        except Exception:
                            pass
                    records[device_id].append(summary)
    
    return {"records": records}

@app.delete("/api/records/{device_id}/{session_id}")
def delete_record(device_id: str, session_id: str):
    output_dir = "output"
    session_path = os.path.join(output_dir, device_id, session_id)
    
    if os.path.exists(session_path) and os.path.isdir(session_path):
        try:
            shutil.rmtree(session_path)
            
            # Clean up device folder if it's empty now
            device_path = os.path.join(output_dir, device_id)
            if not os.listdir(device_path):
                os.rmdir(device_path)
                
            return {"status": "success", "message": "Record deleted successfully."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete record: {str(e)}")
    else:
        raise HTTPException(status_code=404, detail="Record not found.")

@app.get("/api/reports/download/{device_id}/{session_id}")
def download_report(device_id: str, session_id: str):
    output_dir = "output"
    session_path = os.path.join(output_dir, device_id, session_id)
    if not os.path.exists(session_path) or not os.path.isdir(session_path):
        raise HTTPException(status_code=404, detail="Record not found.")
        
    zip_filename = f"{device_id}_{session_id}"
    zip_path = os.path.join(output_dir, zip_filename)
    
    try:
        shutil.make_archive(zip_path, 'zip', session_path)
        return FileResponse(path=zip_path + ".zip", filename=zip_filename + ".zip", media_type="application/zip")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
