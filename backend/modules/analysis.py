"""
analysis.py - DroidScout
Artifact analysis: file categorisation, scoring, APK triage, IOCs, timeline.
"""

import hashlib
import json
import math
import re
import time
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


FILE_CATEGORIES = {
    "images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic",
               ".tiff", ".raw", ".cr2", ".nef"},
    "videos": {".mp4", ".avi", ".mkv", ".mov", ".3gp", ".webm", ".ts",
               ".flv", ".wmv", ".m4v"},
    "audio": {".mp3", ".wav", ".aac", ".flac", ".ogg", ".m4a", ".wma",
              ".opus", ".amr"},
    "documents": {".pdf", ".doc", ".docx", ".txt", ".xlsx", ".xls", ".csv",
                  ".pptx", ".odt", ".rtf", ".md", ".xml", ".vcf", ".json"},
    "archives": {".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz"},
    "databases": {".db", ".sqlite", ".sqlite3"},
    "apk": {".apk"},
}

LARGE_FILE_THRESHOLD_MB = 100
RECENT_DAYS = 7
MAX_DISPLAY_FLAGS = 250

SUSPICIOUS_KEYWORDS = {
    "mod", "premium", "crack", "hack", "dump", "backup", "secret", "hidden",
    "patched", "unlocked", "bypass", "stealth", "keylogger", "spy",
}

BENIGN_HIDDEN_NAMES = {
    ".nomedia", ".database_uuid", ".thumbnails", ".thumbs", ".stickerthumbs",
    ".statuses", ".links", ".wamocache", ".trash",
}

BENIGN_PATH_HINTS = {
    "/.thumbnails/", "/.thumbs/", "/.stickerthumbs/", "/.wamocache/",
    "/cache/", "/cached/", "/code_cache/",
}

DANGEROUS_APK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}

IOC_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.I),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "ip": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "phone": re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)"),
    "hash": re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.I),
    "package": re.compile(r"\b[a-zA-Z][\w]*(?:\.[a-zA-Z][\w-]*){2,}\b"),
}

SENSITIVE_PATTERNS = {
    "otp_or_banking": re.compile(r"\b(otp|one[-\s]?time|bank|account|iban|easypaisa|jazzcash|wallet|verify|verification|pin)\b", re.I),
    "credential_keyword": re.compile(r"\b(password|passwd|pwd|api[_-]?key|secret|token|bearer|login)\b", re.I),
}


class AnalysisModule:
    """Analyses evidence collected by AcquisitionModule."""

    def __init__(self, output_dir: str = "output", status_callback=None):
        self.output_dir = Path(output_dir)
        self.evidence_dir = self.output_dir / "evidence"
        self.reports_dir = self.output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._status_cb = status_callback or (lambda msg: None)
        self.file_metadata = self._load_file_metadata()
        self.hash_data = self._load_hash_data()

    def _load_file_metadata(self) -> dict:
        path = self.evidence_dir / "file_metadata.json"
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            files = data.get("files", data)
            return files if isinstance(files, dict) else {}
        except Exception:
            return {}

    def _load_hash_data(self) -> dict:
        path = self.output_dir / "hashes" / "hashes.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8")).get("hashes", {})
        except Exception:
            return {}

    def _category(self, path: Path) -> str:
        ext = path.suffix.lower()
        for cat, exts in FILE_CATEGORIES.items():
            if ext in exts:
                return cat
        return "other"

    def _rel_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.evidence_dir)).replace("\\", "/")
        except ValueError:
            return str(path).replace("\\", "/")

    def _device_meta_for(self, path: Path) -> dict:
        rel = self._rel_path(path)
        return self.file_metadata.get(rel, {})

    def _sha256_for_rel(self, rel: str) -> str:
        data = self.hash_data.get(rel) or self.hash_data.get(rel.replace("/", "\\"))
        return data.get("sha256", "") if isinstance(data, dict) else ""

    def _file_signature(self, path: Path) -> dict:
        try:
            with open(path, "rb") as fh:
                head = fh.read(512)
        except Exception as exc:
            return {"kind": "unreadable", "mime": "application/octet-stream", "error": str(exc)}

        if head.startswith(b"PK\x03\x04"):
            return {"kind": "apk_or_zip" if path.suffix.lower() == ".apk" else "zip", "mime": "application/zip"}
        if head.startswith(b"%PDF"):
            return {"kind": "pdf", "mime": "application/pdf"}
        if head.startswith(b"SQLite format 3\x00"):
            return {"kind": "sqlite", "mime": "application/x-sqlite3"}
        if head.startswith(b"\xff\xd8\xff"):
            return {"kind": "jpeg", "mime": "image/jpeg"}
        if head.startswith(b"\x89PNG\r\n\x1a\n"):
            return {"kind": "png", "mime": "image/png"}
        if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
            return {"kind": "gif", "mime": "image/gif"}
        if len(head) > 12 and head[4:8] == b"ftyp":
            return {"kind": "mp4", "mime": "video/mp4"}
        sample = head[: min(len(head), 128)]
        if sample and all((b in (9, 10, 13) or 32 <= b <= 126) for b in sample):
            return {"kind": "text", "mime": "text/plain"}
        return {"kind": "unknown_binary" if head else "empty", "mime": "application/octet-stream"}

    def _entropy(self, path: Path, limit: int = 65536) -> float | None:
        try:
            with open(path, "rb") as fh:
                data = fh.read(limit)
        except Exception:
            return None
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        length = len(data)
        for count in counts:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def _extension_matches_signature(self, ext: str, signature_kind: str) -> bool:
        expected = {
            ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".png": {"png"}, ".gif": {"gif"},
            ".pdf": {"pdf"}, ".db": {"sqlite"}, ".sqlite": {"sqlite"}, ".sqlite3": {"sqlite"},
            ".zip": {"zip", "apk_or_zip"}, ".apk": {"apk_or_zip", "zip"},
            ".mp4": {"mp4"}, ".m4v": {"mp4"}, ".3gp": {"mp4"},
            ".txt": {"text"}, ".csv": {"text"}, ".md": {"text"}, ".xml": {"text"},
            ".json": {"text"}, ".vcf": {"text"},
        }
        return signature_kind in expected.get(ext, {signature_kind})

    def _file_meta(self, path: Path) -> dict:
        stat = path.stat()
        rel = self._rel_path(path)
        device_meta = self._device_meta_for(path)
        signature = self._file_signature(path)
        entropy = None
        if (
            stat.st_size <= 50 * 1_048_576
            and (
                not path.suffix
                or path.suffix.lower() in FILE_CATEGORIES["archives"] | {".apk"}
                or signature.get("kind") in {"unknown_binary", "apk_or_zip", "zip"}
            )
        ):
            entropy = self._entropy(path)
        local_mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()
        return {
            "name": path.name,
            "path": str(path),
            "relative_path": rel,
            "extension": path.suffix.lower(),
            "category": self._category(path),
            "size_bytes": stat.st_size,
            "size_mb": round(stat.st_size / 1_048_576, 3),
            "modified_time": device_meta.get("device_modified_time") or local_mtime,
            "device_modified_time": device_meta.get("device_modified_time"),
            "local_acquired_time": local_mtime,
            "created_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "source": device_meta.get("source", "manual_import" if rel.startswith("imports/") else "adb"),
            "remote_path": device_meta.get("remote_path", ""),
            "signature": signature,
            "entropy": entropy,
            "sha256": self._sha256_for_rel(rel),
        }

    def collect_files(self) -> list:
        if not self.evidence_dir.exists():
            print("[-] Evidence directory missing. Run 'acquire' first.")
            return []
        files = []
        for p in self.evidence_dir.rglob("*"):
            if p.is_file():
                try:
                    files.append(self._file_meta(p))
                except (OSError, PermissionError):
                    continue
        return files

    def categorize(self, files: list) -> dict:
        buckets = defaultdict(lambda: {"count": 0, "total_size_bytes": 0, "files": []})
        for f in files:
            c = f["category"]
            buckets[c]["count"] += 1
            buckets[c]["total_size_bytes"] += f["size_bytes"]
            buckets[c]["files"].append(f["path"])
        return {
            cat: {
                "count": d["count"],
                "total_size_bytes": d["total_size_bytes"],
                "total_size_mb": round(d["total_size_bytes"] / 1_048_576, 2),
                "files": d["files"],
            }
            for cat, d in buckets.items()
        }

    def large_files(self, files: list, threshold_mb: float = LARGE_FILE_THRESHOLD_MB) -> list:
        return [f for f in files if f["size_mb"] >= threshold_mb]

    def recent_files(self, files: list, days: int = RECENT_DAYS) -> list:
        cutoff = datetime.now() - timedelta(days=days)
        result = []
        for f in files:
            try:
                if datetime.fromisoformat(f["modified_time"]) >= cutoff:
                    result.append(f)
            except (ValueError, TypeError):
                pass
        return result

    def build_timeline(self, files: list) -> dict:
        buckets = defaultdict(int)
        for f in files:
            try:
                key = datetime.fromisoformat(f["modified_time"]).strftime("%Y-%m")
                buckets[key] += 1
            except (ValueError, TypeError):
                pass
        return dict(sorted(buckets.items()))

    def app_artifact_stats(self, files: list) -> dict:
        app_keywords = {
            "WhatsApp": ["com.whatsapp", "whatsapp"],
            "Telegram": ["org.telegram", "telegram"],
            "Signal": ["org.thoughtcrime", "signal"],
            "Instagram": ["com.instagram", "instagram"],
        }
        stats = {}
        for app, keywords in app_keywords.items():
            matched = [f for f in files if any(kw.lower() in f["path"].lower() for kw in keywords)]
            if not matched:
                continue
            total_bytes = sum(f["size_bytes"] for f in matched)
            by_cat = defaultdict(int)
            for f in matched:
                by_cat[f["category"]] += 1
            stats[app] = {
                "total_files": len(matched),
                "total_size_mb": round(total_bytes / 1_048_576, 2),
                "file_breakdown": dict(by_cat),
            }
        return stats

    def _is_benign_hidden(self, f: dict) -> bool:
        rel = f.get("relative_path", f.get("path", "")).lower().replace("\\", "/")
        name = f.get("name", "").lower()
        return name in BENIGN_HIDDEN_NAMES or any(hint in rel for hint in BENIGN_PATH_HINTS)

    def _severity(self, score: int) -> str:
        if score >= 90:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        return "LOW"

    def _flag_type(self, f: dict, reasons: list[str]) -> str:
        reason_text = " ".join(reasons)
        if f.get("extension") == ".apk":
            return "APK_RISK"
        if "Extension mismatch" in reason_text:
            return "EXTENSION_MISMATCH"
        if "No file extension" in reason_text:
            return "NO_EXTENSION_FILE"
        if "Archive" in reason_text:
            return "ARCHIVE_RISK"
        if "Duplicate SHA-256" in reason_text:
            return "DUPLICATE_HASH"
        if "IOC" in reason_text:
            return "IOC_MATCH"
        return "SUSPICIOUS_FILE"

    def _recommended_action(self, severity: str, f: dict, reasons: list[str]) -> str:
        if f.get("extension") == ".apk":
            return "Review APK source, permissions, certificate hash, and install context before execution."
        if severity in ("CRITICAL", "HIGH"):
            return "Prioritize manual review, preserve hash, and correlate with timeline and communication artifacts."
        if any("No file extension" in r for r in reasons):
            return "Identify true file type using signature and inspect origin folder."
        return "Review artifact context and correlate with related files before drawing conclusions."

    def _hash_groups(self, files: list) -> dict:
        groups = defaultdict(list)
        for f in files:
            sha = f.get("sha256")
            if sha and not sha.startswith("ERROR"):
                groups[sha].append(f.get("relative_path") or f.get("path"))
        return {sha: paths for sha, paths in groups.items() if len(set(paths)) > 1}

    def _apk_static_analysis(self, f: dict) -> dict:
        path = Path(f["path"])
        info = {
            "file": f.get("path"),
            "package_name": "",
            "app_label": "",
            "version": "",
            "permissions": [],
            "dangerous_permissions": [],
            "certificate_sha256": "",
            "parse_status": "not_analyzed",
        }
        if f.get("extension") != ".apk" and f.get("signature", {}).get("kind") != "apk_or_zip":
            return info
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                info["parse_status"] = "zip_readable"
                cert_name = next((n for n in names if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))), "")
                if cert_name:
                    info["certificate_sha256"] = hashlib.sha256(zf.read(cert_name)).hexdigest()
                if "AndroidManifest.xml" in names:
                    raw = zf.read("AndroidManifest.xml")
                    text = raw.decode("utf-8", errors="ignore")
                    perms = sorted(set(re.findall(r"android\.permission\.[A-Z0-9_]+", text)))
                    info["permissions"] = perms
                    info["dangerous_permissions"] = [p for p in perms if p in DANGEROUS_APK_PERMISSIONS]
                    pkg = re.search(r"package=\"([^\"]+)\"", text)
                    if pkg:
                        info["package_name"] = pkg.group(1)
                if not info["permissions"]:
                    info["parse_status"] = "binary_manifest_limited"
        except Exception as exc:
            info["parse_status"] = f"failed:{exc}"
        return info

    def analyze_apks(self, files: list) -> list:
        return [
            self._apk_static_analysis(f)
            for f in files
            if f.get("extension") == ".apk" or f.get("signature", {}).get("kind") == "apk_or_zip"
        ]

    def detect_forensic_flags(self, files: list, large: list, recent: list) -> list:
        duplicate_hashes = self._hash_groups(files)
        dup_lookup = {}
        for _, paths in duplicate_hashes.items():
            for p in paths:
                dup_lookup[p] = paths

        apk_lookup = {a["file"]: a for a in self.analyze_apks(files)}
        flags = []
        for f in files:
            score = 0
            reasons = []
            rel = f.get("relative_path", f.get("path", "")).replace("\\", "/")
            rel_lower = rel.lower()
            name_lower = f.get("name", "").lower()
            ext = f.get("extension", "")
            category = f.get("category", "other")
            benign_hidden = self._is_benign_hidden(f)

            if not ext and not benign_hidden:
                score += 25
                reasons.append("No file extension; possible renamed or obfuscated artifact.")
                if f.get("size_mb", 0) >= 10:
                    score += 15
                    reasons.append("No-extension file is larger than 10 MB.")

            if ext == ".apk" or f.get("signature", {}).get("kind") == "apk_or_zip":
                score += 35
                reasons.append("APK or APK-like ZIP package found in acquired storage.")
                if any(part in rel_lower for part in ("download", "whatsapp", "telegram", "documents", "shared")):
                    score += 20
                    reasons.append("APK is located in user/shared storage rather than an app install location.")
                dangerous = apk_lookup.get(f["path"], {}).get("dangerous_permissions", [])
                if dangerous:
                    score += min(35, 10 + len(dangerous) * 5)
                    reasons.append(f"APK requests risky permissions: {', '.join(dangerous[:5])}.")

            if ext in FILE_CATEGORIES["archives"]:
                score += 20
                reasons.append("Archive file may contain packaged or staged data.")
                if any(part in rel_lower for part in ("download", "documents", "whatsapp", "telegram")):
                    score += 15
                    reasons.append("Archive appears in a user, document, or messaging-app folder.")

            keyword_hits = sorted(k for k in SUSPICIOUS_KEYWORDS if k in name_lower)
            if keyword_hits:
                score += min(30, 10 + len(keyword_hits) * 8)
                reasons.append(f"Suspicious filename keyword(s): {', '.join(keyword_hits)}.")

            if f.get("size_mb", 0) >= 500:
                score += 35
                reasons.append(f"Very large file ({f['size_mb']:.1f} MB) may indicate bulk transfer or exfiltration.")
            elif category not in ("videos", "images", "audio") and f.get("size_mb", 0) >= 100:
                score += 25
                reasons.append(f"Large non-media file ({f['size_mb']:.1f} MB) warrants review.")

            if f.get("name", "").startswith(".") and not benign_hidden:
                score += 18
                reasons.append("Hidden dot-prefixed file outside known benign cache locations.")

            sig = f.get("signature", {})
            sig_kind = sig.get("kind", "")
            if ext and sig_kind not in ("empty", "text", "unknown_binary", "unreadable") and not self._extension_matches_signature(ext, sig_kind):
                score += 30
                reasons.append(f"Extension mismatch: extension {ext} but file signature looks like {sig_kind}.")
            if not ext and sig_kind not in ("empty", "unknown_binary", "unreadable"):
                score += 8
                reasons.append(f"No-extension file signature appears to be {sig_kind}.")

            entropy = f.get("entropy")
            if entropy is not None and entropy >= 7.5 and (not ext or ext in FILE_CATEGORIES["archives"] or ext == ".apk"):
                score += 12
                reasons.append(f"High entropy ({entropy}) suggests compressed, encrypted, or packed content.")

            dup_paths = dup_lookup.get(rel)
            if dup_paths:
                score += 12
                reasons.append(f"Duplicate SHA-256 hash appears in {len(set(dup_paths))} paths.")

            if "/sent/" in rel_lower and category in ("documents", "archives", "other"):
                score += 10
                reasons.append("File appears in a messaging sent folder.")

            if score < 20 or (benign_hidden and score < 45):
                continue

            severity = self._severity(score)
            flags.append({
                "severity": severity,
                "type": self._flag_type(f, reasons),
                "description": f"{f.get('name')} scored {score}: {reasons[0]}",
                "file": f["path"],
                "relative_path": rel,
                "score": score,
                "reasons": reasons,
                "category": category,
                "source": f.get("source", "adb"),
                "recommended_action": self._recommended_action(severity, f, reasons),
                "signature": sig,
                "entropy": entropy,
                "sha256": f.get("sha256", ""),
                "apk": apk_lookup.get(f["path"]),
                "device_modified_time": f.get("device_modified_time"),
                "local_acquired_time": f.get("local_acquired_time"),
            })

        flags.sort(key=lambda x: (x["score"], x["severity"]), reverse=True)
        return flags

    def extract_iocs(self, files: list, max_per_file: int = 25) -> dict:
        searchable_exts = {".txt", ".csv", ".json", ".xml", ".log", ".md", ".vcf", ""}
        results = defaultdict(list)
        for f in files:
            sig_kind = f.get("signature", {}).get("kind")
            if f.get("extension") not in searchable_exts and sig_kind != "text":
                continue
            if not f.get("extension") and sig_kind != "text":
                continue
            if f.get("size_bytes", 0) > 5 * 1_048_576 and f.get("extension") not in {".txt", ".csv", ".json", ".xml", ".log", ".md", ".vcf"}:
                continue
            path = Path(f["path"])
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[:500000]
            except Exception:
                continue
            for kind, pattern in IOC_PATTERNS.items():
                seen = set()
                for match in pattern.finditer(text):
                    value = match.group(0).strip(".,);]")
                    if value in seen:
                        continue
                    seen.add(value)
                    start = max(0, match.start() - 40)
                    end = min(len(text), match.end() + 40)
                    results[kind].append({
                        "value": value,
                        "file": f["path"],
                        "source": f.get("source", "adb"),
                        "snippet": text[start:end].replace("\n", " ")[:160],
                    })
                    if len(seen) >= max_per_file:
                        break
            for kind, pattern in SENSITIVE_PATTERNS.items():
                match = pattern.search(text)
                if match:
                    start = max(0, match.start() - 40)
                    end = min(len(text), match.end() + 40)
                    results[kind].append({
                        "value": match.group(0),
                        "file": f["path"],
                        "source": f.get("source", "adb"),
                        "snippet": text[start:end].replace("\n", " ")[:160],
                    })
        return {k: v[:500] for k, v in results.items()}

    def build_unified_timeline(self, files: list, flags: list) -> list:
        events = []
        flag_by_file = defaultdict(list)
        for fl in flags:
            if fl.get("file"):
                flag_by_file[fl["file"]].append(fl)
        for f in files:
            ts = f.get("modified_time")
            if not ts:
                continue
            linked = flag_by_file.get(f["path"], [])
            events.append({
                "timestamp": ts,
                "event_type": "file_modified",
                "source": f.get("source", "adb"),
                "severity": linked[0]["severity"] if linked else "INFO",
                "description": f.get("name", ""),
                "file": f.get("path"),
                "score": linked[0]["score"] if linked else 0,
            })
        for fl in flags[:MAX_DISPLAY_FLAGS]:
            ts = fl.get("device_modified_time") or fl.get("local_acquired_time")
            if ts:
                events.append({
                    "timestamp": ts,
                    "event_type": "suspicious_finding",
                    "source": fl.get("source", "adb"),
                    "severity": fl.get("severity", "LOW"),
                    "description": fl.get("description", ""),
                    "file": fl.get("file"),
                    "score": fl.get("score", 0),
                })
        events.sort(key=lambda e: e.get("timestamp", ""))
        return events[:2000]

    def cluster_timeline(self, events: list, window_minutes: int = 30) -> list:
        suspicious = [e for e in events if e.get("severity") in ("CRITICAL", "HIGH") and e.get("timestamp")]
        clusters = []
        current = []
        for e in suspicious:
            try:
                ts = datetime.fromisoformat(e["timestamp"])
            except Exception:
                continue
            if not current:
                current = [(ts, e)]
            elif ts - current[-1][0] <= timedelta(minutes=window_minutes):
                current.append((ts, e))
            else:
                if len(current) >= 2:
                    clusters.append(self._cluster_summary(current))
                current = [(ts, e)]
        if len(current) >= 2:
            clusters.append(self._cluster_summary(current))
        return clusters[:50]

    def _cluster_summary(self, cluster: list) -> dict:
        events = [e for _, e in cluster]
        return {
            "start": cluster[0][0].isoformat(),
            "end": cluster[-1][0].isoformat(),
            "event_count": len(events),
            "max_score": max(e.get("score", 0) for e in events),
            "files": [e.get("file") for e in events if e.get("file")][:10],
            "description": f"{len(events)} high-risk events occurred close together.",
        }

    def analyze(self) -> dict:
        print(f"\n{'='*60}")
        print("  DroidScout  -  Analysis Module")
        print(f"{'='*60}")

        print("\n[>] Collecting evidence files ...")
        self._status_cb("Collecting and categorizing evidence files...")
        t0 = time.time()
        files = self.collect_files()
        if not files:
            print("[-] No files found in evidence directory.")
            return {}

        print(f"[+] {len(files)} file(s) found")
        print("[>] Categorising ...")
        categories = self.categorize(files)
        print("[>] Filtering large files ...")
        large = self.large_files(files)
        print("[>] Detecting recent activity ...")
        recent = self.recent_files(files)
        print("[>] Building timeline ...")
        timeline = self.build_timeline(files)
        print("[>] Analysing app artefacts ...")
        app_stats = self.app_artifact_stats(files)
        print("[>] Running score-based forensic detection ...")
        flags_all = self.detect_forensic_flags(files, large, recent)
        flags_display = flags_all[:MAX_DISPLAY_FLAGS]
        print("[>] Analysing APK files ...")
        apk_analysis = self.analyze_apks(files)
        print("[>] Extracting IOCs and sensitive indicators ...")
        iocs = self.extract_iocs(files)
        print("[>] Building unified timeline ...")
        unified_timeline = self.build_unified_timeline(files, flags_display)
        clusters = self.cluster_timeline(unified_timeline)

        total_bytes = sum(f["size_bytes"] for f in files)
        elapsed = round(time.time() - t0, 2)
        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "duration_seconds": elapsed,
            "summary": {
                "total_files": len(files),
                "total_size_bytes": total_bytes,
                "total_size_mb": round(total_bytes / 1_048_576, 2),
                "total_size_gb": round(total_bytes / 1_073_741_824, 3),
                "total_findings": len(flags_all),
                "displayed_findings": len(flags_display),
            },
            "file_categories": categories,
            "large_files": large,
            "recent_activity": {
                "window_days": RECENT_DAYS,
                "count": len(recent),
                "files": recent[:100],
                "timestamp_source": "device_modified_time when available, otherwise local_acquired_time",
            },
            "timeline": timeline,
            "unified_timeline": unified_timeline,
            "timeline_clusters": clusters,
            "app_artifacts": app_stats,
            "apk_analysis": apk_analysis,
            "iocs": iocs,
            "forensic_flags": flags_display,
            "forensic_flags_all": flags_all,
            "all_files": files,
        }

        out = self.reports_dir / "analysis.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"\n[+] Analysis complete in {elapsed}s")
        print(f"    Files analysed : {len(files)}")
        print(f"    Total size     : {report['summary']['total_size_mb']} MB")
        print(f"    Findings       : {len(flags_all)} ({len(flags_display)} displayed)")
        print(f"[+] Analysis saved : {out}")
        return report
