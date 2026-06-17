"""
adb_helper.py — DroidScout
Low-level wrapper around ADB shell commands.
All forensic acquisition goes through this class.
"""

import subprocess
import sys
import os
from pathlib import Path


class ADBHelper:
    """
    Wraps ADB commands for forensic-safe communication with Android devices.
    Uses subprocess (never os.system) to avoid shell injection and capture stderr.
    """

    def __init__(self, serial: str = None):
        self.serial = serial
        self._verify_adb()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_adb(self):
        """Abort early if ADB is not on PATH."""
        try:
            r = subprocess.run(
                ["adb", "version"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode != 0:
                raise EnvironmentError("ADB returned non-zero exit code.")
        except FileNotFoundError:
            print("[-] ADB not found. Install Android Platform Tools and add to PATH.")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print("[-] ADB timed out. Is the ADB daemon running?")
            sys.exit(1)

    def _run(self, args: list, timeout: int = 120) -> tuple:
        """
        Execute a subprocess command.

        Returns:
            (returncode: int, stdout: str, stderr: str)
        """
        if self.serial and args[0] == "adb" and len(args) > 1 and args[1] not in ["start-server", "kill-server", "devices", "version"]:
            args.insert(1, "-s")
            args.insert(2, self.serial)

        try:
            r = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Timed out after {timeout}s"
        except Exception as e:
            return -1, "", str(e)

    # ------------------------------------------------------------------
    # Server management
    # ------------------------------------------------------------------

    def start_server(self) -> bool:
        """Start the ADB server."""
        code, stdout, stderr = self._run(["adb", "start-server"], timeout=30)
        return code == 0

    def kill_server(self) -> bool:
        """Kill the ADB server."""
        code, stdout, stderr = self._run(["adb", "kill-server"], timeout=30)
        return code == 0

    def connect_tcpip(self, host: str, port: int = 5555) -> tuple:
        """Connect to a device over Wi-Fi ADB."""
        target = f"{host}:{port}"
        code, stdout, stderr = self._run(["adb", "connect", target], timeout=30)
        output = (stdout or stderr or "").strip()
        return code == 0 and ("connected" in output.lower() or "already connected" in output.lower()), output

    def disconnect_tcpip(self, host: str = "", port: int = 5555) -> tuple:
        """Disconnect one Wi-Fi ADB target, or all TCP/IP targets when host is empty."""
        target = f"{host}:{port}" if host else ""
        args = ["adb", "disconnect"] + ([target] if target else [])
        code, stdout, stderr = self._run(args, timeout=30)
        output = (stdout or stderr or "").strip()
        return code == 0, output

    # ------------------------------------------------------------------
    # Device detection
    # ------------------------------------------------------------------

    def check_device_connected(self) -> bool:
        """Return True if at least one authorised device is online."""
        _, stdout, _ = self._run(["adb", "devices"])
        lines = stdout.strip().splitlines()
        # Skip header; keep lines that end with 'device' (not 'offline'/'unauthorized')
        active = [l for l in lines[1:] if l.strip().endswith("\tdevice")]
        return len(active) > 0

    def get_connected_devices(self) -> list:
        """Return serial numbers of all connected authorised devices."""
        _, stdout, _ = self._run(["adb", "devices"])
        devices = []
        for line in stdout.strip().splitlines()[1:]:
            parts = line.strip().split("\t")
            if len(parts) == 2 and parts[1] == "device":
                devices.append(parts[0])
        return devices

    # ------------------------------------------------------------------
    # Shell execution
    # ------------------------------------------------------------------

    def shell(self, command: str, timeout: int = 30) -> tuple:
        """
        Run `adb shell <command>`.

        Returns:
            (returncode: int, output: str)
        """
        code, stdout, stderr = self._run(["adb", "shell", command], timeout=timeout)
        return code, stdout

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    def pull(self, remote_path: str, local_path: str, timeout: int = 600) -> tuple:
        """
        Pull a remote path (file or directory) to a local destination.

        Returns:
            (success: bool, message: str)
        """
        os.makedirs(local_path, exist_ok=True)
        code, stdout, stderr = self._run(
            ["adb", "pull", remote_path, local_path],
            timeout=timeout
        )
        if code == 0:
            return True, stdout.strip()
        return False, stderr.strip()

    def path_exists(self, remote_path: str) -> bool:
        """Check whether a path exists on the connected device."""
        _, output = self.shell(
            f'[ -e "{remote_path}" ] && echo __EXISTS__ || echo __MISSING__'
        )
        return "__EXISTS__" in output

    # ------------------------------------------------------------------
    # Device metadata
    # ------------------------------------------------------------------

    def get_device_props(self) -> dict:
        """
        Read build properties via `getprop` and return as a dict.
        Covers manufacturer, model, Android version, SDK, serial, etc.
        """
        _, output = self.shell("getprop")
        raw_props = {}
        for line in output.splitlines():
            if line.startswith("[") and "]: [" in line:
                key, val = line.split("]: [", 1)
                key = key.lstrip("[")
                val = val.rstrip("]")
                raw_props[key] = val

        return {
            "manufacturer":    raw_props.get("ro.product.manufacturer", ""),
            "model":           raw_props.get("ro.product.model", ""),
            "android_version": raw_props.get("ro.build.version.release", ""),
            "sdk_version":     raw_props.get("ro.build.version.sdk", ""),
            "build_id":        raw_props.get("ro.build.id", ""),
            "serial":          raw_props.get("ro.serialno", self.serial),
            "device_name":     raw_props.get("ro.product.name", ""),
            "fingerprint":     raw_props.get("ro.build.fingerprint", ""),
            "cpu_abi":         raw_props.get("ro.product.cpu.abi", ""),
            "locale":          raw_props.get("ro.product.locale", ""),
            "carrier":         raw_props.get("gsm.operator.alpha", ""),
            "sim_state":       raw_props.get("gsm.sim.state", ""),
            "network_type":    raw_props.get("gsm.network.type", ""),
        }

    def get_battery_info(self) -> str:
        """Return raw `dumpsys battery` output."""
        _, output = self.shell("dumpsys battery", timeout=15)
        return output

    def get_package_list(self) -> str:
        """Return list of installed packages (with APK paths)."""
        _, output = self.shell("pm list packages -f", timeout=30)
        return output

    def get_logcat(self, lines: int = 10000) -> str:
        """
        Capture the last N logcat lines from the device buffer.
        Uses `-d` (dump and exit) so it does not block.
        """
        code, stdout, stderr = self._run(
            ["adb", "logcat", "-d", "-t", str(lines)],
            timeout=180
        )
        return stdout

    # ------------------------------------------------------------------
    # Network information
    # ------------------------------------------------------------------

    def get_wifi_info(self) -> str:
        """Return dumpsys wifi output (SSID history, connection state)."""
        _, output = self.shell("dumpsys wifi", timeout=20)
        return output

    def get_network_info(self) -> str:
        """Return IP routing table and interface config."""
        _, routes = self.shell("ip route", timeout=10)
        _, ifaces = self.shell("ip addr", timeout=10)
        return f"=== IP ROUTES ===\n{routes}\n\n=== IP ADDRESSES ===\n{ifaces}"

    # ------------------------------------------------------------------
    # Screenshot
    # ------------------------------------------------------------------

    def take_screenshot(self, local_path: str) -> tuple:
        """
        Capture the device screen and save as PNG at local_path.
        Uses exec-out to stream raw bytes without writing to device storage.
        Returns (success: bool, message: str).
        """
        import subprocess, os
        args = ["adb"]
        if self.serial:
            args += ["-s", self.serial]
        args += ["exec-out", "screencap", "-p"]
        try:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            result = subprocess.run(args, capture_output=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                with open(local_path, "wb") as f:
                    f.write(result.stdout)
                return True, f"Screenshot saved ({len(result.stdout)} bytes)"
            return False, result.stderr.decode(errors="replace").strip()
        except Exception as e:
            return False, str(e)

    # ------------------------------------------------------------------
    # Running processes
    # ------------------------------------------------------------------

    def get_running_processes(self) -> str:
        """Return process list via `ps -A`."""
        _, output = self.shell("ps -A", timeout=20)
        if not output.strip():
            _, output = self.shell("ps", timeout=20)
        return output

    # ------------------------------------------------------------------
    # Permission helpers (Android 10+ restricts content providers)
    # ------------------------------------------------------------------

    def _grant(self, permission: str):
        """Grant a permission to com.android.shell (needed on Android 10+)."""
        return self._run(["adb", "shell", "pm", "grant", "com.android.shell", permission], timeout=10)

    def _revoke(self, permission: str):
        """Revoke a permission from com.android.shell after querying."""
        return self._run(["adb", "shell", "pm", "revoke", "com.android.shell", permission], timeout=10)

    def _query_with_permission(self, permission: str, uri: str,
                                projection: str, extra: str = "", timeout: int = 30) -> str:
        """Grant permission, run content query, revoke permission."""
        self._grant(permission)
        _, output = self.shell(
            f"content query --uri {uri} --projection {projection} {extra}",
            timeout=timeout,
        )
        self._revoke(permission)
        return output

    def _query_with_permission_status(self, permission: str, uri: str,
                                      projection: str, extra: str = "", timeout: int = 30) -> dict:
        """Grant permission, query content provider, and return structured status."""
        g_code, g_out, g_err = self._grant(permission)
        grant_msg = f"{g_out}\n{g_err}".strip()
        if g_code != 0:
            lowered = grant_msg.lower()
            if "not a changeable permission type" in lowered or "hard restricted" in lowered or "permission denied" in lowered:
                status = "blocked_by_android_policy"
            else:
                status = "permission_denied"
            return {"status": status, "output": "", "error": grant_msg, "rows": 0}

        code, output = self.shell(
            f"content query --uri {uri} --projection {projection} {extra}",
            timeout=timeout,
        )
        self._revoke(permission)
        rows = output.count("Row:")
        if code != 0:
            lowered = output.lower()
            status = "blocked_by_android_policy" if "permission" in lowered or "security" in lowered else "failed"
        else:
            status = "collected" if rows else "empty"
        return {"status": status, "output": output, "error": "" if code == 0 else output, "rows": rows}

    # ------------------------------------------------------------------
    # Contacts / Call logs / SMS
    # ------------------------------------------------------------------

    def get_contacts(self) -> str:
        """Query phone contacts — grants READ_CONTACTS for Android 10+."""
        output = self._query_with_permission(
            "android.permission.READ_CONTACTS",
            "content://contacts/phones",
            "display_name:number:type",
        )
        # Fallback: try SIM phonebook
        if not output.strip() or "Row:" not in output:
            _, sim = self.shell(
                "content query --uri content://icc/adn --projection name:number",
                timeout=20,
            )
            if "Row:" in sim:
                output = (output + "\n" + sim).strip()
        return output

    def get_contacts_status(self) -> dict:
        result = self._query_with_permission_status(
            "android.permission.READ_CONTACTS",
            "content://contacts/phones",
            "display_name:number:type",
        )
        if result["rows"] == 0:
            _, sim = self.shell(
                "content query --uri content://icc/adn --projection name:number",
                timeout=20,
            )
            if "Row:" in sim:
                result["output"] = (result["output"] + "\n" + sim).strip()
                result["rows"] = result["output"].count("Row:")
                result["status"] = "collected"
        return result

    def get_call_logs(self) -> str:
        """Query call log — grants READ_CALL_LOG for Android 10+."""
        return self._query_with_permission(
            "android.permission.READ_CALL_LOG",
            "content://call_log/calls",
            "number:duration:type:date:name",
            extra="--sort 'date DESC' --limit 500",
        )

    def get_call_logs_status(self) -> dict:
        return self._query_with_permission_status(
            "android.permission.READ_CALL_LOG",
            "content://call_log/calls",
            "number:duration:type:date:name",
            extra="--sort 'date DESC' --limit 500",
        )

    def get_sms(self) -> str:
        """Query SMS — grants READ_SMS for Android 10+."""
        phone_sms = self._query_with_permission(
            "android.permission.READ_SMS",
            "content://sms",
            "address:body:date:type:read",
            extra="--sort 'date DESC' --limit 500",
        )
        # Also try SIM SMS
        _, sim_sms = self.shell(
            "content query --uri content://icc/sms --projection address:body:date:type",
            timeout=20,
        )
        if "Row:" in sim_sms:
            phone_sms = (phone_sms + "\n" + sim_sms).strip()
        return phone_sms

    def get_sms_status(self) -> dict:
        result = self._query_with_permission_status(
            "android.permission.READ_SMS",
            "content://sms",
            "address:body:date:type:read",
            extra="--sort 'date DESC' --limit 500",
        )
        _, sim_sms = self.shell(
            "content query --uri content://icc/sms --projection address:body:date:type",
            timeout=20,
        )
        if "Row:" in sim_sms:
            result["output"] = (result["output"] + "\n" + sim_sms).strip()
            result["rows"] = result["output"].count("Row:")
            result["status"] = "collected"
        return result

    def get_phone_number(self) -> str:
        """Try multiple methods to get the device's own phone number."""
        # Method 1: telephony registry
        _, out = self.shell("dumpsys telephony.registry", timeout=15)
        import re
        match = re.search(r'mPhoneNumber\s*=\s*([+\d]+)', out)
        if match:
            return match.group(1)
        # Method 2: iphonesubinfo service
        _, out2 = self.shell("service call iphonesubinfo 1", timeout=10)
        parts = re.findall(r"'(.*?)'", out2)
        number = "".join(parts).strip().replace(".", "")
        if number and number not in ("", "0"):
            return number
        # Method 3: settings
        _, out3 = self.shell("settings get global sim_state", timeout=5)
        return out3.strip() or "Unknown"

    def get_sim_info(self) -> str:
        """Get SIM / carrier information."""
        fields = [
            ("Carrier",       "getprop gsm.operator.alpha"),
            ("MCC/MNC",       "getprop gsm.operator.numeric"),
            ("Network Type",  "getprop gsm.network.type"),
            ("SIM State",     "getprop gsm.sim.state"),
            ("SIM Serial",    "getprop ro.serialno"),
            ("IMEI",          "service call iphonesubinfo 1"),
        ]
        lines = []
        for label, cmd in fields:
            _, out = self.shell(cmd, timeout=8)
            lines.append(f"{label}: {out.strip()}")
        return "\n".join(lines)
