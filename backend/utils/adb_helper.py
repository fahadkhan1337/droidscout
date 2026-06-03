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
