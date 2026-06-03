"""
analysis.py — DroidScout
Artifact analysis: file categorisation, timeline, app stats, forensic flags.
"""

import json
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


# ---------------------------------------------------------------------------
# File-type taxonomy used throughout the analysis pipeline
# ---------------------------------------------------------------------------

FILE_CATEGORIES = {
    "images":    {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic",
                  ".tiff", ".raw", ".cr2", ".nef"},
    "videos":    {".mp4", ".avi", ".mkv", ".mov", ".3gp", ".webm", ".ts",
                  ".flv", ".wmv", ".m4v"},
    "audio":     {".mp3", ".wav", ".aac", ".flac", ".ogg", ".m4a", ".wma",
                  ".opus", ".amr"},
    "documents": {".pdf", ".doc", ".docx", ".txt", ".xlsx", ".xls", ".csv",
                  ".pptx", ".odt", ".rtf", ".md"},
    "archives":  {".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz"},
    "databases": {".db", ".sqlite", ".sqlite3"},
    "apk":       {".apk"},
}

LARGE_FILE_THRESHOLD_MB = 100
RECENT_DAYS = 7


class AnalysisModule:
    """
    Analyses all evidence files collected by AcquisitionModule.

    Outputs
    -------
    - output/reports/analysis.json   (full analysis used by ReportingModule)
    """

    def __init__(self, output_dir: str = "output", status_callback=None):
        self.output_dir   = Path(output_dir)
        self.evidence_dir = self.output_dir / "evidence"
        self.reports_dir  = self.output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._status_cb = status_callback or (lambda msg: None)

    # ------------------------------------------------------------------
    # File metadata helpers
    # ------------------------------------------------------------------

    def _category(self, path: Path) -> str:
        ext = path.suffix.lower()
        for cat, exts in FILE_CATEGORIES.items():
            if ext in exts:
                return cat
        return "other"

    def _file_meta(self, path: Path) -> dict:
        stat = path.stat()
        return {
            "name":          path.name,
            "path":          str(path),
            "extension":     path.suffix.lower(),
            "category":      self._category(path),
            "size_bytes":    stat.st_size,
            "size_mb":       round(stat.st_size / 1_048_576, 3),
            "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "created_time":  datetime.fromtimestamp(stat.st_ctime).isoformat(),
        }

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def collect_files(self) -> list:
        """Walk evidence directory and return metadata list for every file."""
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

    # ------------------------------------------------------------------
    # Categorisation
    # ------------------------------------------------------------------

    def categorize(self, files: list) -> dict:
        """
        Group files by category.

        Returns
        -------
        {category: {count, total_size_bytes, total_size_mb, files: [paths]}}
        """
        buckets = defaultdict(lambda: {"count": 0, "total_size_bytes": 0, "files": []})
        for f in files:
            c = f["category"]
            buckets[c]["count"]            += 1
            buckets[c]["total_size_bytes"] += f["size_bytes"]
            buckets[c]["files"].append(f["path"])

        return {
            cat: {
                "count":            d["count"],
                "total_size_bytes": d["total_size_bytes"],
                "total_size_mb":    round(d["total_size_bytes"] / 1_048_576, 2),
                "files":            d["files"],
            }
            for cat, d in buckets.items()
        }

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------

    def large_files(self, files: list,
                    threshold_mb: float = LARGE_FILE_THRESHOLD_MB) -> list:
        """Return files exceeding *threshold_mb*."""
        return [f for f in files if f["size_mb"] >= threshold_mb]

    def recent_files(self, files: list, days: int = RECENT_DAYS) -> list:
        """Return files modified within the last *days* days."""
        cutoff = datetime.now() - timedelta(days=days)
        result = []
        for f in files:
            try:
                if datetime.fromisoformat(f["modified_time"]) >= cutoff:
                    result.append(f)
            except (ValueError, TypeError):
                pass
        return result

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def build_timeline(self, files: list) -> dict:
        """
        Build a monthly bucket of file-modification counts.

        Returns
        -------
        Ordered dict: {"YYYY-MM": count, ...}
        """
        buckets = defaultdict(int)
        for f in files:
            try:
                key = datetime.fromisoformat(f["modified_time"]).strftime("%Y-%m")
                buckets[key] += 1
            except (ValueError, TypeError):
                pass
        return dict(sorted(buckets.items()))

    # ------------------------------------------------------------------
    # App-specific artifact stats
    # ------------------------------------------------------------------

    def app_artifact_stats(self, files: list) -> dict:
        """
        Identify files belonging to known messaging/social apps and
        return per-app statistics.
        """
        app_keywords = {
            "WhatsApp": ["com.whatsapp", "whatsapp"],
            "Telegram":  ["org.telegram",  "telegram"],
            "Signal":    ["org.thoughtcrime", "signal"],
            "Instagram": ["com.instagram",  "instagram"],
        }

        stats = {}
        for app, keywords in app_keywords.items():
            matched = [
                f for f in files
                if any(kw.lower() in f["path"].lower() for kw in keywords)
            ]
            if not matched:
                continue

            total_bytes = sum(f["size_bytes"] for f in matched)
            by_cat      = defaultdict(int)
            for f in matched:
                by_cat[f["category"]] += 1

            stats[app] = {
                "total_files":    len(matched),
                "total_size_mb":  round(total_bytes / 1_048_576, 2),
                "file_breakdown": dict(by_cat),
            }

        return stats

    # ------------------------------------------------------------------
    # ★ Forensic Flag Detection — YOUR CONTRIBUTION
    # ------------------------------------------------------------------

    def detect_forensic_flags(self,
                               files: list,
                               large: list,
                               recent: list) -> list:
        """
        Identify forensically significant artefacts and return a flag list.

        Each flag must be a dict with:
            severity    : "HIGH" | "MEDIUM" | "LOW"
            type        : short label, e.g. "LARGE_FILE", "APK_SIDELOAD"
            description : human-readable explanation
            file        : (optional) triggering file path

        TODO — Implement your flagging rules here.
        -------------------------------------------------------
        Suggested rules to consider:

        HIGH severity
        - Files modified in the last 24 hours      (very recent evidence)
        - APK files present in /sdcard             (potential sideloaded malware)
        - Files > 500 MB (especially videos)       (bulk data exfil indicator)

        MEDIUM severity
        - Files with no extension                  (possible obfuscation)
        - Files > 100 MB that are not videos       (suspicious large non-media)
        - More than 500 WhatsApp media files       (high-volume communication)

        LOW severity
        - Hidden files (name starts with '.')      (intentional concealment)
        - Duplicate filenames in different dirs    (copied evidence?)
        - Archive files (.zip / .rar) in Downloads (potential data packaging)

        Return an empty list if nothing suspicious is found.
        -------------------------------------------------------
        """
        flags = []
        now = datetime.now()

        # ── HIGH severity ───────────────────────────────────────────────

        # Files modified in the last 24 hours (very fresh evidence)
        cutoff_24h = now - timedelta(hours=24)
        very_recent = []
        for f in files:
            try:
                if datetime.fromisoformat(f["modified_time"]) >= cutoff_24h:
                    very_recent.append(f)
            except (ValueError, TypeError):
                pass
        if very_recent:
            flags.append({
                "severity": "HIGH",
                "type": "VERY_RECENT_FILES",
                "description": f"{len(very_recent)} file(s) were modified in the last 24 hours — potential active evidence.",
                "file": very_recent[0]["path"] if very_recent else None,
            })

        # APK files anywhere in sdcard (potential sideloaded malware)
        apk_files = [f for f in files if f.get("extension") == ".apk"]
        for apk in apk_files:
            flags.append({
                "severity": "HIGH",
                "type": "APK_SIDELOAD",
                "description": f"APK file found outside Play Store — possible sideloaded or malicious app.",
                "file": apk["path"],
            })

        # Files larger than 500 MB (bulk data exfiltration indicator)
        for f in files:
            if f.get("size_mb", 0) >= 500:
                flags.append({
                    "severity": "HIGH",
                    "type": "MASSIVE_FILE",
                    "description": f"File exceeds 500 MB ({f['size_mb']:.1f} MB) — possible bulk data exfiltration.",
                    "file": f["path"],
                })

        # ── MEDIUM severity ─────────────────────────────────────────────

        # Files with no extension (possible obfuscation / hidden data)
        no_ext = [f for f in files if not f.get("extension") and not f["name"].startswith(".")]
        if no_ext:
            flags.append({
                "severity": "MEDIUM",
                "type": "NO_EXTENSION_FILES",
                "description": f"{len(no_ext)} file(s) have no extension — possible obfuscation or renamed files.",
                "file": no_ext[0]["path"] if no_ext else None,
            })

        # Large non-video files > 100 MB (suspicious)
        for f in large:
            if f.get("category") not in ("videos",) and f.get("size_mb", 0) >= 100:
                flags.append({
                    "severity": "MEDIUM",
                    "type": "LARGE_NON_VIDEO",
                    "description": f"Non-video file exceeds 100 MB ({f['size_mb']:.1f} MB) — warrants investigation.",
                    "file": f["path"],
                })

        # High-volume WhatsApp media (> 500 files)
        wa_files = [f for f in files if "whatsapp" in f.get("path", "").lower()]
        if len(wa_files) > 500:
            flags.append({
                "severity": "MEDIUM",
                "type": "HIGH_VOLUME_WHATSAPP",
                "description": f"{len(wa_files)} WhatsApp media files found — unusually high communication volume.",
                "file": None,
            })

        # Database files (SQLite) — may contain app data
        db_files = [f for f in files if f.get("extension") in (".db", ".sqlite", ".sqlite3")]
        if db_files:
            flags.append({
                "severity": "MEDIUM",
                "type": "DATABASE_FILES",
                "description": f"{len(db_files)} database file(s) found — may contain messages, contacts or app data.",
                "file": db_files[0]["path"],
            })

        # ── LOW severity ────────────────────────────────────────────────

        # Hidden files (name starts with '.')
        hidden = [f for f in files if f["name"].startswith(".")]
        if hidden:
            flags.append({
                "severity": "LOW",
                "type": "HIDDEN_FILES",
                "description": f"{len(hidden)} hidden file(s) found (dot-prefixed names) — intentional concealment possible.",
                "file": hidden[0]["path"],
            })

        # Duplicate filenames in different directories
        from collections import Counter
        name_counts = Counter(f["name"] for f in files)
        dupes = [name for name, count in name_counts.items() if count > 1]
        if dupes:
            flags.append({
                "severity": "LOW",
                "type": "DUPLICATE_FILENAMES",
                "description": f"{len(dupes)} filename(s) appear in multiple directories — possible copied/moved evidence.",
                "file": None,
            })

        # Archive files in Downloads (potential data packaging)
        archive_in_downloads = [
            f for f in files
            if f.get("extension") in (".zip", ".rar", ".tar", ".gz", ".7z")
            and "download" in f.get("path", "").lower()
        ]
        for arc in archive_in_downloads:
            flags.append({
                "severity": "LOW",
                "type": "ARCHIVE_IN_DOWNLOADS",
                "description": f"Archive file in Downloads folder — possible data packaging for exfiltration.",
                "file": arc["path"],
            })

        return flags

    # ------------------------------------------------------------------
    # Master pipeline
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """
        Run the full analysis pipeline and persist results to
        output/reports/analysis.json.

        Returns
        -------
        Complete analysis dict (also consumed by ReportingModule)
        """
        print(f"\n{'='*60}")
        print("  DroidScout  —  Analysis Module")
        print(f"{'='*60}")

        print("\n[>] Collecting evidence files ...")
        self._status_cb("Collecting and categorizing evidence files...")
        t0    = time.time()
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

        print("[>] Running forensic flag detection ...")
        flags = self.detect_forensic_flags(files, large, recent)

        total_bytes = sum(f["size_bytes"] for f in files)
        elapsed     = round(time.time() - t0, 2)

        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "duration_seconds":   elapsed,
            "summary": {
                "total_files":    len(files),
                "total_size_bytes": total_bytes,
                "total_size_mb":  round(total_bytes / 1_048_576, 2),
                "total_size_gb":  round(total_bytes / 1_073_741_824, 3),
            },
            "file_categories":  categories,
            "large_files":      large,
            "recent_activity": {
                "window_days": RECENT_DAYS,
                "count":       len(recent),
                "files":       recent[:100],   # cap to keep JSON manageable
            },
            "timeline":         timeline,
            "app_artifacts":    app_stats,
            "forensic_flags":   flags,
            "all_files":        files,
        }

        out = self.reports_dir / "analysis.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

        print(f"\n[+] Analysis complete in {elapsed}s")
        print(f"    Files analysed : {len(files)}")
        print(f"    Total size     : {report['summary']['total_size_mb']} MB")
        print(f"    Forensic flags : {len(flags)}")
        print(f"[+] Analysis saved : {out}")

        return report
