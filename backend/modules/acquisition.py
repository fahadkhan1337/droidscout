"""
acquisition.py — DroidScout
Logical data acquisition from Android device via ADB.
Only targets non-root accessible storage (NIST SP 800-86 compliant).
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path

from utils.adb_helper import ADBHelper

try:
    from tqdm import tqdm
    _TQDM = True
except ImportError:
    _TQDM = False


# ---------------------------------------------------------------------------
# Acquisition targets — all accessible on non-rooted Android devices
# ---------------------------------------------------------------------------

USER_STORAGE_PATHS = [
    "/sdcard/DCIM/",
    "/sdcard/Pictures/",
    "/sdcard/Download/",
    "/sdcard/Documents/",
    "/sdcard/Movies/",
    "/sdcard/Music/",
    "/sdcard/Android/media/",   # Android 11+ app media (WhatsApp, etc.)
]

APP_PATHS = {
    "WhatsApp": "/sdcard/Android/media/com.whatsapp/WhatsApp/",
    "Telegram":  "/sdcard/Android/data/org.telegram.messenger/files/",
    "Signal":    "/sdcard/Android/data/org.thoughtcrime.securesms/",
    "Instagram": "/sdcard/Android/media/com.instagram.android/",
}


class AcquisitionModule:
    """
    Performs forensically sound logical data acquisition via ADB.

    Workflow
    --------
    1. Verify device connection
    2. Collect device metadata (getprop, dumpsys battery, pm list packages)
    3. Pull user storage directories
    4. Pull app-specific media
    5. Capture logcat
    6. Write acquisition manifest (JSON)
    """

    def __init__(self, serial: str = None, output_dir: str = "output", status_callback=None):
        self.output_dir   = Path(output_dir)
        self.evidence_dir = self.output_dir / "evidence"
        self.reports_dir  = self.output_dir / "reports"
        self.hashes_dir   = self.output_dir / "hashes"
        self.adb          = ADBHelper(serial)
        self.log_entries  = []
        self.file_metadata = {}
        self.communication_status = {}
        self.session_id   = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._status_cb   = status_callback or (lambda msg: None)

        for d in [self.evidence_dir, self.reports_dir, self.hashes_dir]:
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal logging
    # ------------------------------------------------------------------

    def _log(self, msg: str, level: str = "INFO"):
        entry = {"timestamp": datetime.now().isoformat(), "level": level, "message": msg}
        self.log_entries.append(entry)
        icons = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]", "ERROR": "[-]"}
        print(f"  {icons.get(level, '[*]')} {msg}")

    def _local_rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.evidence_dir)).replace("\\", "/")
        except ValueError:
            return str(path).replace("\\", "/")

    def _iso_from_epoch(self, value: str) -> str:
        try:
            return datetime.fromtimestamp(float(value)).isoformat()
        except Exception:
            return ""

    def _record_local_metadata(self, local_path: Path, remote_path: str = "", source: str = "adb"):
        try:
            st = local_path.stat()
        except OSError:
            return
        self.file_metadata[self._local_rel(local_path)] = {
            "source": source,
            "remote_path": remote_path,
            "size_bytes": st.st_size,
            "device_modified_time": "",
            "local_acquired_time": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "metadata_status": "local_fallback",
        }

    def _capture_remote_metadata(self, remote_root: str, local_root: Path):
        """
        Best-effort Android-side metadata capture. Some Android builds restrict
        shell/find/stat behavior; failures are non-fatal and local timestamps remain.
        """
        remote_root = remote_root.rstrip("/")
        cmd = (
            f"find '{remote_root}' -type f 2>/dev/null | "
            "while read f; do stat -c '%n\t%s\t%Y' \"$f\" 2>/dev/null; done"
        )
        _, output = self.adb.shell(cmd, timeout=180)
        rows = 0
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            remote_path, size, mtime = parts
            suffix = remote_path[len(remote_root):].lstrip("/")
            local_path = local_root / suffix
            if not local_path.exists():
                continue
            rel = self._local_rel(local_path)
            self.file_metadata[rel] = {
                "source": "adb",
                "remote_path": remote_path,
                "size_bytes": int(size) if size.isdigit() else local_path.stat().st_size,
                "device_modified_time": self._iso_from_epoch(mtime),
                "local_acquired_time": datetime.fromtimestamp(local_path.stat().st_mtime).isoformat(),
                "metadata_status": "device_stat",
            }
            rows += 1
        if rows:
            self._log(f"  -> captured device timestamps for {rows} file(s)", "SUCCESS")
        else:
            for fp in local_root.rglob("*"):
                if fp.is_file():
                    self._record_local_metadata(fp, source="adb")

    # ------------------------------------------------------------------
    # Device verification
    # ------------------------------------------------------------------

    def verify_device(self) -> bool:
        print("\n[>] Checking ADB device connection...")
        if not self.adb.check_device_connected():
            print("[-] No authorised device found.")
            print("    -> Enable USB Debugging on the device")
            print("    -> Accept the 'Allow USB Debugging' prompt on screen")
            return False
        devices = self.adb.get_connected_devices()
        self._log(f"Device online: {devices[0]}", "SUCCESS")
        return True

    # ------------------------------------------------------------------
    # Step 1 — Device metadata
    # ------------------------------------------------------------------

    def acquire_device_info(self) -> dict:
        print("\n[>] Acquiring device metadata...")
        self._status_cb("Acquiring device metadata & battery info...")

        props = self.adb.get_device_props()
        (self.evidence_dir / "device_info.json").write_text(
            json.dumps(props, indent=2), encoding="utf-8"
        )
        self._log("device_info.json saved", "SUCCESS")

        self._status_cb("Acquiring battery info...")
        battery = self.adb.get_battery_info()
        (self.evidence_dir / "battery_info.txt").write_text(battery, encoding="utf-8")
        self._log("battery_info.txt saved", "SUCCESS")

        self._status_cb("Listing installed packages...")
        packages = self.adb.get_package_list()
        (self.evidence_dir / "installed_packages.txt").write_text(packages, encoding="utf-8")
        self._log(f"installed_packages.txt saved ({packages.count(chr(10))} packages)", "SUCCESS")

        return props

    # ------------------------------------------------------------------
    # Step 2 — Logcat
    # ------------------------------------------------------------------

    def acquire_logcat(self):
        print("\n[>] Capturing device logcat...")
        self._status_cb("Capturing logcat (system logs)...")
        logcat = self.adb.get_logcat()
        path = self.evidence_dir / "logcat.txt"
        path.write_text(logcat, encoding="utf-8", errors="replace")
        self._log(f"logcat.txt saved ({len(logcat):,} bytes)", "SUCCESS")

    # ------------------------------------------------------------------
    # Step 3 — Pull a single directory
    # ------------------------------------------------------------------

    def _pull_directory(self, remote: str, category: str) -> dict:
        """
        Pull one remote directory into evidence/<category>/<dirname>.

        Returns a result dict logged into the manifest.
        """
        folder_name = Path(remote.rstrip("/")).name
        local_dest  = self.evidence_dir / category / folder_name

        result = {
            "remote_path":  remote,
            "local_path":   str(local_dest),
            "status":       "skipped",
            "files_pulled": 0,
            "timestamp":    datetime.now().isoformat(),
        }

        if not self.adb.path_exists(remote):
            self._log(f"Not found on device: {remote}", "WARNING")
            result["status"] = "not_found"
            return result

        self._log(f"Pulling {remote} ...")
        self._status_cb(f"Pulling {remote}...")
        success, message = self.adb.pull(remote, str(local_dest))

        if success:
            count = sum(1 for p in local_dest.rglob("*") if p.is_file())
            self._capture_remote_metadata(remote, local_dest)
            result["status"]       = "success"
            result["files_pulled"] = count
            self._log(f"  -> {count} file(s) pulled from {remote}", "SUCCESS")
        else:
            result["status"] = "error"
            result["error"]  = message
            self._log(f"  -> Failed: {message}", "ERROR")

        return result

    # ------------------------------------------------------------------
    # Step 4 — User storage
    # ------------------------------------------------------------------

    def acquire_user_storage(self) -> list:
        print("\n[>] Acquiring user storage directories...")
        paths = tqdm(USER_STORAGE_PATHS, desc="  Directories") if _TQDM else USER_STORAGE_PATHS
        return [self._pull_directory(p, "user_storage") for p in paths]

    # ------------------------------------------------------------------
    # Step 5 — App-specific media
    # ------------------------------------------------------------------

    def acquire_app_media(self) -> list:
        print("\n[>] Acquiring app-specific media...")
        results = []
        for app_name, remote in APP_PATHS.items():
            self._log(f"Checking {app_name} ...")
            self._status_cb(f"Checking {app_name} media...")
            r = self._pull_directory(remote, f"apps/{app_name.lower()}")
            r["app"] = app_name
            results.append(r)
        return results

    # ------------------------------------------------------------------
    # Step 6 — Network information
    # ------------------------------------------------------------------

    def acquire_network_info(self):
        print("\n[>] Acquiring network information...")
        self._status_cb("Acquiring Wi-Fi and network info...")
        wifi = self.adb.get_wifi_info()
        (self.evidence_dir / "wifi_info.txt").write_text(wifi, encoding="utf-8", errors="replace")
        net = self.adb.get_network_info()
        (self.evidence_dir / "network_info.txt").write_text(net, encoding="utf-8", errors="replace")
        self._log("wifi_info.txt and network_info.txt saved", "SUCCESS")

    # ------------------------------------------------------------------
    # Step 7 — Screenshot
    # ------------------------------------------------------------------

    def acquire_screenshot(self):
        print("\n[>] Taking device screenshot...")
        self._status_cb("Capturing device screenshot...")
        path = str(self.evidence_dir / "screenshot.png")
        success, message = self.adb.take_screenshot(path)
        if success:
            self._log(f"screenshot.png saved — {message}", "SUCCESS")
        else:
            self._log(f"Screenshot failed: {message}", "WARNING")

    # ------------------------------------------------------------------
    # Step 8 — Running processes
    # ------------------------------------------------------------------

    def acquire_processes(self):
        print("\n[>] Acquiring running processes...")
        self._status_cb("Capturing running processes...")
        output = self.adb.get_running_processes()
        (self.evidence_dir / "running_processes.txt").write_text(output, encoding="utf-8", errors="replace")
        self._log(f"running_processes.txt saved ({output.count(chr(10))} processes)", "SUCCESS")

    # ------------------------------------------------------------------
    # Step 9 — Contacts / Call logs / SMS
    # ------------------------------------------------------------------

    def _write_comm_result(self, name: str, filename: str, result: dict):
        output = result.get("output", "")
        (self.evidence_dir / filename).write_text(output, encoding="utf-8", errors="replace")
        rows = result.get("rows", output.count("Row:"))
        status = result.get("status", "collected" if rows else "empty")
        self.communication_status[name] = {
            "status": status,
            "rows": rows,
            "file": filename,
            "source": "adb",
            "error": result.get("error", "")[:500],
        }
        level = "SUCCESS" if status == "collected" else ("WARNING" if status in ("empty", "blocked_by_android_policy", "permission_denied") else "ERROR")
        self._log(f"{filename} saved ({rows} entries, status: {status})", level)

    def acquire_communication_data(self):
        print("\n[>] Acquiring communication data (contacts, calls, SMS)...")

        self._status_cb("Extracting phone number & SIM info...")
        phone_number = self.adb.get_phone_number()
        sim_info = self.adb.get_sim_info()
        (self.evidence_dir / "sim_info.txt").write_text(
            f"Phone Number: {phone_number}\n\n{sim_info}", encoding="utf-8", errors="replace"
        )
        self._log(f"sim_info.txt saved (number: {phone_number})", "SUCCESS")

        self._status_cb("Querying contacts (granting READ_CONTACTS)...")
        contacts = self.adb.get_contacts_status()
        self._write_comm_result("contacts", "contacts.txt", contacts)

        self._status_cb("Querying call logs (granting READ_CALL_LOG)...")
        calls = self.adb.get_call_logs_status()
        self._write_comm_result("calls", "call_logs.txt", calls)

        self._status_cb("Querying SMS (granting READ_SMS)...")
        sms = self.adb.get_sms_status()
        self._write_comm_result("sms", "sms.txt", sms)

    # ------------------------------------------------------------------
    # Master entry point
    # ------------------------------------------------------------------

    def acquire_all(self, options: dict = None) -> dict:
        """
        Run the full (or selective) acquisition pipeline and return the manifest dict.

        Pipeline
        --------
        verify device -> device info -> logcat -> network -> screenshot ->
        processes -> contacts/sms -> user storage -> app media -> manifest
        """
        if options is None:
            options = {
                "user_storage": True, "app_media": True, "metadata_logcat": True,
                "network_info": True, "screenshot": True, "processes": True,
                "communication": True,
            }

        print(f"\n{'='*60}")
        print("  DroidScout  —  Acquisition Module")
        print(f"  Session : {self.session_id}")
        print(f"{'='*60}")

        if not self.verify_device():
            return {}

        t0 = time.time()

        device_info = {}
        storage_results = []
        app_results = []

        if options.get("metadata_logcat", True):
            device_info = self.acquire_device_info()
            self.acquire_logcat()

        if options.get("network_info", True):
            self.acquire_network_info()

        if options.get("screenshot", True):
            self.acquire_screenshot()

        if options.get("processes", True):
            self.acquire_processes()

        if options.get("communication", True):
            self.acquire_communication_data()

        if options.get("user_storage", True):
            self._status_cb("Pulling user storage directories...")
            storage_results = self.acquire_user_storage()

        if options.get("app_media", True):
            app_results = self.acquire_app_media()

        elapsed = round(time.time() - t0, 2)

        metadata_path = self.evidence_dir / "file_metadata.json"
        for fp in self.evidence_dir.rglob("*"):
            if fp.is_file() and self._local_rel(fp) not in self.file_metadata:
                self._record_local_metadata(fp, source="adb")
        metadata_path.write_text(json.dumps({
            "generated_at": datetime.now().isoformat(),
            "files": self.file_metadata,
        }, indent=2), encoding="utf-8")

        manifest = {
            "tool":              "DroidScout v1.0.0",
            "session_id":        self.session_id,
            "acquisition_time":  datetime.now().isoformat(),
            "duration_seconds":  elapsed,
            "device_info":       device_info,
            "storage":           storage_results,
            "apps":              app_results,
            "communication":     self.communication_status,
            "file_metadata":     {"path": str(metadata_path), "total_files": len(self.file_metadata)},
            "log":               self.log_entries,
        }

        manifest_path = self.evidence_dir / "acquisition_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        total_pulled = sum(r.get("files_pulled", 0) for r in storage_results + app_results)
        print(f"\n[+] Acquisition complete in {elapsed}s")
        print(f"[+] Total files pulled : {total_pulled}")
        print(f"[+] Manifest saved     : {manifest_path}")

        return manifest
