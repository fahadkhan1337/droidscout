"""
reporting.py — DroidTrace
Generates JSON, CSV, and an interactive HTML dashboard from analysis data.
"""

import csv
import json
from datetime import datetime
from html import escape
from pathlib import Path


class ReportingModule:
    """
    Reads output/reports/analysis.json + output/hashes/hashes.json
    and produces three report artefacts:

      output/reports/report.json    — structured forensic JSON report
      output/reports/report.csv     — flat file-level CSV summary
      output/reports/dashboard.html — self-contained HTML dashboard (Chart.js)
    """

    def __init__(self, output_dir: str = "output", status_callback=None):
        self.output_dir  = Path(output_dir)
        self.reports_dir = self.output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._status_cb = status_callback or (lambda msg: None)

        self.analysis: dict = {}
        self.hash_data: dict = {}
        self.device_info: dict = {}
        self.manifest: dict = {}
        self.case_meta: dict = {}
        self.packages: list = []
        self.file_flags: list = []   # investigator-set manual flags from Explorer

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def load_data(self):
        """Load analysis.json, hashes.json, device_info.json, and case metadata."""
        analysis_path = self.reports_dir / "analysis.json"
        if analysis_path.exists():
            self.analysis = json.loads(analysis_path.read_text(encoding="utf-8"))

        hash_path = self.output_dir / "hashes" / "hashes.json"
        if hash_path.exists():
            self.hash_data = json.loads(hash_path.read_text(encoding="utf-8"))

        device_path = self.output_dir / "evidence" / "device_info.json"
        if device_path.exists():
            self.device_info = json.loads(device_path.read_text(encoding="utf-8"))

        manifest_path = self.output_dir / "evidence" / "acquisition_manifest.json"
        if manifest_path.exists():
            self.manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        else:
            self.manifest = {}

        case_path = self.output_dir / "case_metadata.json"
        if case_path.exists():
            self.case_meta = json.loads(case_path.read_text(encoding="utf-8"))
        else:
            self.case_meta = {}

        pkg_path = self.output_dir / "evidence" / "installed_packages.txt"
        if pkg_path.exists():
            raw = pkg_path.read_text(encoding="utf-8", errors="replace")
            pkgs = []
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    # format: package:/path/to/app.apk=com.package.name
                    part = line[len("package:"):]
                    if "=" in part:
                        _, pkg_name = part.rsplit("=", 1)
                    else:
                        pkg_name = part.split("/")[-1].replace(".apk", "")
                    pkgs.append(pkg_name.strip())
            self.packages = sorted(pkgs)
        else:
            self.packages = []

    # ------------------------------------------------------------------
    # 1. JSON report
    # ------------------------------------------------------------------

    def generate_json(self) -> Path:
        """Write a structured forensic JSON report."""
        coverage = self._acquisition_coverage()
        chain = self._chain_of_custody()
        report = {
            "report_metadata": {
                "tool":           "DroidTrace v1.0.0",
                "generated_at":   datetime.now().isoformat(),
                "report_type":    "Mobile Forensic Analysis Report",
                "project":        "Open-Source Mobile Forensic Toolkit — LGU FYP",
                "student":        "Muhammad Fahad Khan (Fall-2022-072/B)",
            },
            "device_information": self.device_info,
            "case_metadata":      self.case_meta,
            "chain_of_custody":   chain,
            "acquisition_coverage": coverage,
            "evidence_summary":   self.analysis.get("summary", {}),
            "file_categories":    self.analysis.get("file_categories", {}),
            "analysis": {
                "large_files":      self.analysis.get("large_files", []),
                "recent_activity":  self.analysis.get("recent_activity", {}),
                "app_artifacts":    self.analysis.get("app_artifacts", {}),
                "timeline":         self.analysis.get("timeline", {}),
                "unified_timeline": self.analysis.get("unified_timeline", []),
                "timeline_clusters": self.analysis.get("timeline_clusters", []),
                "apk_analysis":     self.analysis.get("apk_analysis", []),
                "iocs":             self.analysis.get("iocs", {}),
                "forensic_flags":   self.analysis.get("forensic_flags", []),
                "forensic_flags_all_count": len(self.analysis.get("forensic_flags_all", [])),
            },
            "integrity": {
                "algorithm":      self.hash_data.get("algorithm", "SHA-256"),
                "total_hashed":   self.hash_data.get("total_files", 0),
                "generated_at":   self.hash_data.get("generated_at", "N/A"),
                "sample_hashes":  dict(list(self.hash_data.get("hashes", {}).items())[:5]),
            },
        }

        path = self.reports_dir / "report.json"
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"[+] JSON report   -> {path}")
        return path

    # ------------------------------------------------------------------
    # 2. CSV report
    # ------------------------------------------------------------------

    def generate_csv(self) -> Path:
        """Write a flat CSV with one row per acquired file."""
        path  = self.reports_dir / "report.csv"
        files = self.analysis.get("all_files", [])
        stored_hashes = self.hash_data.get("hashes", {})

        fields = ["name", "category", "extension", "size_mb",
                  "modified_time", "device_modified_time", "local_acquired_time",
                  "source", "signature", "entropy", "sha256", "path"]

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for f in files:
                # Best-effort hash lookup by partial path match
                sha = "N/A"
                for rel, hdata in stored_hashes.items():
                    if rel.endswith(f.get("name", "!!!")):
                        sha = hdata.get("sha256", "N/A")
                        break

                writer.writerow({
                    "name":          f.get("name", ""),
                    "category":      f.get("category", ""),
                    "extension":     f.get("extension", ""),
                    "size_mb":       f.get("size_mb", 0),
                    "modified_time": f.get("modified_time", ""),
                    "device_modified_time": f.get("device_modified_time", ""),
                    "local_acquired_time": f.get("local_acquired_time", ""),
                    "source":        f.get("source", ""),
                    "signature":     f.get("signature", {}).get("kind", ""),
                    "entropy":       f.get("entropy", ""),
                    "sha256":        sha,
                    "path":          f.get("path", ""),
                })

        print(f"[+] CSV report    -> {path}")
        return path

    # ------------------------------------------------------------------
    # 3. HTML dashboard — helpers
    # ------------------------------------------------------------------

    def _info_rows(self) -> str:
        if not self.device_info:
            return '<div class="kv"><span class="k">Status</span><span class="v">No device info available</span></div>'
        labels = {
            "manufacturer":    "Manufacturer",
            "model":           "Model",
            "android_version": "Android Version",
            "sdk_version":     "SDK Level",
            "build_id":        "Build ID",
            "serial":          "Serial Number",
            "device_name":     "Device Name",
            "fingerprint":     "Build Fingerprint",
            "cpu_abi":         "CPU ABI",
            "carrier":         "Carrier",
            "sim_state":       "SIM State",
            "network_type":    "Network Type",
        }
        rows = []
        for k, label in labels.items():
            v = self.device_info.get(k, "N/A") or "N/A"
            rows.append(f'<div class="kv"><span class="k">{label}</span><span class="v" title="{v}">{v}</span></div>')
        return "\n".join(rows)

    def _app_cards(self) -> str:
        apps_cfg = [
            ("WhatsApp",  "#25D366", "whatsapp"),
            ("Telegram",  "#2AABEE", "telegram"),
            ("Signal",    "#3A76F0", "signal"),
            ("Instagram", "#E1306C", "instagram"),
        ]
        app_data = self.analysis.get("app_artifacts", {})
        cards = []
        for name, colour, app_key in apps_cfg:
            d = app_data.get(name)
            style = f"background:var(--s1);padding:14px;border-left:3px solid {colour};"
            if d:
                rows = "".join(
                    f'<div style="display:flex;justify-content:space-between;padding:4px 0;'
                    f'border-bottom:1px solid var(--bd2);font-size:11px">'
                    f'<span style="color:var(--t3)">{c}</span>'
                    f'<span style="color:var(--t1);font-family:var(--mono)">{n}</span></div>'
                    for c, n in [("Total Files", d["total_files"]), ("Size", f'{d["total_size_mb"]} MB')]
                    + list(d.get("file_breakdown", {}).items())
                )
                gallery_btn = (
                    f'<a href="{self._explorer_url}?app={app_key}" target="_blank"'
                    f' style="display:inline-flex;align-items:center;gap:5px;margin-top:10px;'
                    f'padding:4px 10px;font-size:10px;font-weight:700;text-decoration:none;'
                    f'border:1px solid {colour}40;color:{colour};transition:.15s;letter-spacing:.3px;"'
                    f' onmouseover="this.style.background=\'{colour}22\'"'
                    f' onmouseout="this.style.background=\'transparent\'">'
                    f'<svg width="11" height="11" fill="none" stroke="currentColor" viewBox="0 0 24 24">'
                    f'<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" '
                    f'd="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14"></path></svg>'
                    f'View in Gallery</a>'
                )
                inner = rows + gallery_btn
            else:
                inner = '<div style="color:var(--t3);font-size:11px;padding:6px 0;">Not found / no media</div>'
            cards.append(
                f'<div style="{style}">'
                f'<div style="font-size:13px;font-weight:700;color:var(--t1);margin-bottom:8px;">{name}</div>'
                f'{inner}</div>'
            )
        return "\n".join(cards)

    def _acquisition_coverage(self) -> dict:
        storage = self.manifest.get("storage", [])
        apps = self.manifest.get("apps", [])
        communication = self.manifest.get("communication", {})
        return {
            "storage": [{"path": s.get("remote_path"), "status": s.get("status"), "files": s.get("files_pulled", 0)} for s in storage],
            "apps": [{"app": s.get("app"), "path": s.get("remote_path"), "status": s.get("status"), "files": s.get("files_pulled", 0)} for s in apps],
            "communication": communication,
            "evidence_sources": self.manifest.get("evidence_sources", ["adb"]),
            "limitations": [
                "Non-root logical acquisition cannot access protected app-private data.",
                "Android 16 may block SMS and call-log access unless data is imported or collected through an allowed role/app path.",
            ],
        }

    def _chain_of_custody(self) -> dict:
        return {
            "case_number": self.case_meta.get("case_number", ""),
            "investigator": self.case_meta.get("investigator", ""),
            "notes": self.case_meta.get("notes", ""),
            "acquisition_time": self.manifest.get("acquisition_time", ""),
            "report_generated_at": datetime.now().isoformat(),
            "tool": self.manifest.get("tool", "DroidTrace v1.0.0"),
            "hash_algorithm": self.hash_data.get("algorithm", "SHA-256"),
            "total_hashed": self.hash_data.get("total_files", 0),
            "hash_manifest_generated_at": self.hash_data.get("generated_at", ""),
            "file_metadata": self.manifest.get("file_metadata", {}),
        }

    def _coverage_html(self) -> str:
        coverage = self._acquisition_coverage()
        rows = []
        for item in coverage.get("storage", []):
            rows.append(("Storage", item.get("path", ""), item.get("status", ""), item.get("files", 0)))
        for item in coverage.get("apps", []):
            rows.append((f"App: {item.get('app','')}", item.get("path", ""), item.get("status", ""), item.get("files", 0)))
        for name, item in coverage.get("communication", {}).items():
            rows.append((f"Communication: {name}", item.get("source", "adb"), item.get("status", ""), item.get("rows", 0)))
        if not rows:
            return '<div class="empty">No acquisition coverage data available</div>'
        body = "".join(
            f"<tr><td>{escape(str(kind))}</td><td class=\"mono trunc\">{escape(str(path))}</td>"
            f"<td><span class=\"cbadge\">{escape(str(status))}</span></td><td class=\"mono\">{count}</td></tr>"
            for kind, path, status, count in rows
        )
        return '<table class="dtable"><thead><tr><th>Source</th><th>Path/Method</th><th>Status</th><th>Items</th></tr></thead><tbody>' + body + '</tbody></table>'

    def _flags_html(self) -> str:
        flags = self.analysis.get("forensic_flags", [])
        if not flags:
            return '<div class="empty">No forensic flags detected</div>'
        grouped_new: dict = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for fl in flags:
            grouped_new.setdefault(fl.get("severity", "LOW"), []).append(fl)
        rows_new = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            for fl in grouped_new.get(sev, []):
                key = fl.get("type", "") + "::" + (fl.get("file") or "")
                reasons = fl.get("reasons", [])
                reason_html = "".join(
                    f'<div style="font-size:10px;color:var(--t3);margin-top:2px;">- {escape(str(r))}</div>'
                    for r in reasons[:3]
                )
                action = fl.get("recommended_action", "")
                score = fl.get("score", "")
                fpath = escape(fl.get("file", "")) if fl.get("file") else ""
                rows_new.append(
                    f'<div class="flag-row" data-fkey="{escape(key)}">'
                    f'<span class="fbadge {sev}">{sev}</span>'
                    f'<div style="flex:1;min-width:0">'
                    f'<div class="ftext">{escape(fl.get("type",""))} | score {score} | {escape(fl.get("description",""))}</div>'
                    f'{"<div class=fpath>" + fpath + "</div>" if fpath else ""}'
                    f'{reason_html}'
                    f'{"<div style=\"font-size:10px;color:var(--blu);margin-top:3px;\">Action: " + escape(action) + "</div>" if action else ""}'
                    f'</div>'
                    f'<button class="ack-btn" onclick="toggleAck(this,\'{key.replace(chr(39), "")}\')">Reviewed</button>'
                    f'</div>'
                )
        return "\n".join(rows_new)
        grouped: dict = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for fl in flags:
            grouped.setdefault(fl.get("severity", "LOW"), []).append(fl)
        rows = []
        for sev in ("HIGH", "MEDIUM", "LOW"):
            for fl in grouped.get(sev, []):
                key = fl.get("type", "") + "::" + (fl.get("file") or "")
                rows.append(
                    f'<div class="flag-row" data-fkey="{key}">'
                    f'<span class="fbadge {sev}">{sev}</span>'
                    f'<div style="flex:1;min-width:0"><div class="ftext">{fl.get("type","")} — {fl.get("description","")}</div>'
                    f'{"<div class=fpath>" + fl.get("file","") + "</div>" if fl.get("file") else ""}'
                    f'</div>'
                    f'<button class="ack-btn" onclick="toggleAck(this,\'{key.replace(chr(39), "")}\')">✓ Reviewed</button>'
                    f'</div>'
                )
        return "\n".join(rows)

    def _investigator_flags_html(self) -> str:
        flags = self.file_flags
        if not flags:
            return '<div class="empty">No files flagged by investigator</div>'
        grouped: dict = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for fl in flags:
            grouped.setdefault(fl.get("severity", "LOW"), []).append(fl)
        rows = []
        for sev in ("HIGH", "MEDIUM", "LOW"):
            for fl in grouped.get(sev, []):
                fp   = fl.get("file_path", "")
                note = fl.get("note", "")
                ts   = fl.get("created_at", "")[:19] if fl.get("created_at") else ""
                fname = fp.split("/")[-1] if fp else ""
                rows.append(
                    f'<div class="flag-row">'
                    f'<span class="fbadge {sev}">{sev}</span>'
                    f'<div style="flex:1;min-width:0">'
                    f'<div class="ftext">{fname}'
                    f'{"<span style=\"color:var(--t3);font-size:10px;margin-left:8px;\">" + note + "</span>" if note else ""}'
                    f'</div>'
                    f'<div class="fpath">{fp}</div>'
                    f'{"<div style=\"font-size:10px;color:var(--t3);margin-top:2px;\">Flagged: " + ts + "</div>" if ts else ""}'
                    f'</div></div>'
                )
        return "\n".join(rows)

    def _file_table(self, files: list, empty: str = "No files") -> str:
        if not files:
            return f'<div class="empty">{empty}</div>'
        rows = "".join(
            f'<tr>'
            f'<td>{f.get("name","")}</td>'
            f'<td><span class="cbadge">{f.get("category","")}</span></td>'
            f'<td class="mono">{f.get("size_mb",0):.2f} MB</td>'
            f'<td class="mono">{f.get("modified_time","")[:19]}</td>'
            f'<td class="mono trunc" title="{f.get("path","")}">{f.get("path","")}</td>'
            f'</tr>'
            for f in files
        )
        return (
            '<table class="dtable"><thead><tr>'
            '<th>Filename</th><th>Category</th><th>Size</th>'
            '<th>Modified</th><th>Path</th>'
            '</tr></thead><tbody>' + rows + '</tbody></table>'
        )

    def _packages_html(self) -> str:
        if not self.packages:
            return '<div class="empty">No package list available</div>'
        system_prefixes = ("com.android", "com.google", "com.samsung", "com.qualcomm",
                           "com.mediatek", "com.miui", "android", "com.huawei",
                           "com.lge", "com.htc", "com.sony", "com.oppo", "com.vivo")
        rows = []
        for pkg in self.packages:
            is_sys = pkg.startswith(system_prefixes)
            cls = "" if is_sys else ' class="pkg-3p"'
            rows.append(f'<tr><td{cls} title="{pkg}">{pkg}</td></tr>')
        return f'<table class="pkg-table"><tbody>{"".join(rows)}</tbody></table>'

    def _acq_log_html(self) -> str:
        log = self.manifest.get("log", [])
        if not log:
            return '<div class="empty">No acquisition log available</div>'
        color_map = {"SUCCESS": "var(--grn)", "WARNING": "#e3b341", "ERROR": "var(--red)", "INFO": "var(--t3)"}
        rows = []
        for entry in log:
            level = entry.get("level", "INFO")
            color = color_map.get(level, "var(--t3)")
            ts = entry.get("timestamp", "")[:19]
            msg = entry.get("message", "")
            rows.append(
                f'<div class="log-line">'
                f'<span class="log-ts">{ts}</span>'
                f'<span style="color:{color};font-weight:700;flex-shrink:0;min-width:55px;font-size:10px;text-transform:uppercase">{level}</span>'
                f'<span class="log-msg">{msg}</span></div>'
            )
        return "\n".join(rows)

    def _hash_samples(self) -> str:
        hashes = self.hash_data.get("hashes", {})
        if not hashes:
            return '<div class="empty">No hash data — run acquire first</div>'
        items = []
        for rel, data in list(hashes.items())[:6]:
            items.append(
                f'<div class="hash-row">'
                f'<div class="hr-file">{rel}</div>'
                f'<div class="hr-hash">{data["sha256"]}</div>'
                f'</div>'
            )
        return "\n".join(items)

    # ------------------------------------------------------------------
    # 3. HTML dashboard — main generator
    # ------------------------------------------------------------------

    def generate_html(self) -> Path:
        """Build a self-contained dark-theme forensic HTML dashboard."""

        summary  = self.analysis.get("summary", {})
        cats     = self.analysis.get("file_categories", {})
        timeline = self.analysis.get("timeline", {})
        flags    = self.analysis.get("forensic_flags", [])
        large    = self.analysis.get("large_files", [])[:15]
        recent   = self.analysis.get("recent_activity", {}).get("files", [])[:15]

        cat_labels = json.dumps(list(cats.keys()))
        cat_counts = json.dumps([cats[c]["count"] for c in cats])
        cat_sizes  = json.dumps([cats[c]["total_size_mb"] for c in cats])
        tl_labels  = json.dumps(list(timeline.keys()))
        tl_values  = json.dumps(list(timeline.values()))

        gen_time      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        flag_count    = len(flags)
        flag_color    = "var(--red)" if flag_count else "var(--green)"
        case_number   = self.case_meta.get("case_number", "") or "N/A"
        investigator  = self.case_meta.get("investigator", "") or "N/A"
        notes         = self.case_meta.get("notes", "") or ""
        acq_time      = self.manifest.get("acquisition_time", "N/A")
        acq_duration  = self.manifest.get("duration_seconds", "N/A")
        # Extract device_id / session_id from output path for explorer links
        parts = self.output_dir.parts
        try:
            out_idx   = next(i for i, p in enumerate(parts) if p == "output")
            _device   = parts[out_idx + 1]
            _session  = parts[out_idx + 2]
        except Exception:
            _device, _session = "", ""
        explorer_url = f"/explorer/{_device}/{_session}" if _device and _session else "#"
        self._explorer_url = explorer_url

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>DroidTrace — {case_number} — Forensic Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:  #0d1117;
  --s1:  #161b22;
  --s2:  #1c2128;
  --bd:  #30363d;
  --bd2: #21262d;
  --t1:  #e6edf3;
  --t2:  #8b949e;
  --t3:  #484f58;
  --acc: #e3b341;    /* amber — single accent */
  --red: #f85149;
  --grn: #3fb950;
  --blu: #58a6ff;
  --mono:'Consolas','Courier New',monospace;
}}
html{{scroll-behavior:smooth}}
body{{
  background:var(--bg);color:var(--t1);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  font-size:20px;line-height:1.75;
}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:transparent}}
::-webkit-scrollbar-thumb{{background:var(--bd);border-radius:2px}}

/* ─── TOP BANNER ─────────────────────────────────────────────────── */
.banner{{
  background:var(--s1);
  border-bottom:2px solid var(--acc);
  padding:0 32px;
  display:flex;align-items:stretch;
  position:sticky;top:0;z-index:100;
}}
.banner-brand{{
  display:flex;align-items:center;gap:10px;
  padding:12px 20px 12px 0;
  border-right:1px solid var(--bd);
  margin-right:20px;
}}
.brand-name{{font-size:30px;font-weight:800;letter-spacing:0;color:var(--t1)}}
.brand-name em{{color:var(--acc);font-style:normal}}
.brand-tag{{
  font-size:14px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;
  color:var(--acc);border:1px solid var(--acc);padding:4px 10px;
}}
.banner-meta{{
  display:flex;align-items:center;gap:32px;flex:1;
  font-size:17px;color:var(--t2);
}}
.bm-item{{display:flex;flex-direction:column;gap:1px;padding:10px 0}}
.bm-label{{font-size:14px;font-weight:700;text-transform:uppercase;
           letter-spacing:1px;color:var(--t3)}}
.bm-val{{color:var(--t1);font-family:var(--mono);font-size:17px}}
.banner-actions{{display:flex;align-items:center;gap:8px;padding:10px 0;margin-left:auto}}
.btn-outline{{
  display:inline-flex;align-items:center;gap:5px;
  padding:6px 14px;border:1px solid var(--bd);color:var(--t2);
  font-size:14px;font-weight:600;text-decoration:none;
  transition:.15s;cursor:pointer;background:transparent;
}}
.btn-outline:hover{{border-color:var(--acc);color:var(--acc)}}

/* ─── LAYOUT ─────────────────────────────────────────────────────── */
.layout{{display:flex;min-height:calc(100vh - 57px)}}

/* ─── LEFT SIDEBAR / TOC ─────────────────────────────────────────── */
.sidebar{{
  width:230px;flex-shrink:0;
  background:var(--s1);border-right:1px solid var(--bd);
  position:sticky;top:57px;height:calc(100vh - 57px);
  overflow-y:auto;padding:16px 0;
}}
.toc-head{{
  font-size:14px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;
  color:var(--t3);padding:0 16px 8px;
}}
.toc-link{{
  display:block;padding:10px 18px;font-size:18px;color:var(--t2);
  text-decoration:none;border-left:2px solid transparent;
  transition:.12s;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}}
.toc-link:hover{{color:var(--t1);background:var(--s2)}}
.toc-link.active{{color:var(--acc);border-left-color:var(--acc);background:var(--s2)}}
.toc-sep{{height:1px;background:var(--bd);margin:6px 16px}}

/* ─── MAIN CONTENT ───────────────────────────────────────────────── */
.main{{flex:1;padding:34px 40px;overflow-x:hidden}}

/* ─── SECTION ────────────────────────────────────────────────────── */
.section{{margin-bottom:44px}}
.section,.metric,.ch-panel,.kv,.flag-row{{will-change:transform,opacity}}
.sec-hd{{
  display:flex;align-items:baseline;gap:10px;
  border-bottom:1px solid var(--bd);padding-bottom:8px;margin-bottom:16px;
}}
.sec-num{{font-size:15px;font-weight:700;color:var(--acc);font-family:var(--mono);width:32px}}
.sec-title{{font-size:20px;font-weight:700;text-transform:uppercase;
            letter-spacing:1px;color:var(--t2)}}
.sec-count{{font-size:17px;color:var(--t3);margin-left:auto}}

/* ─── METRICS ROW ────────────────────────────────────────────────── */
.metrics{{display:flex;gap:0;border:1px solid var(--bd)}}
.metric{{
  flex:1;padding:16px 20px;border-right:1px solid var(--bd);
}}
.metric:last-child{{border-right:none}}
.m-val{{font-size:44px;font-weight:800;color:var(--t1);line-height:1;font-family:var(--mono)}}
.m-label{{font-size:18px;color:var(--t2);margin-top:6px}}
.m-sub{{font-size:16px;color:var(--t3);margin-top:3px}}

/* ─── DATA TABLE ─────────────────────────────────────────────────── */
.dtable{{width:100%;border-collapse:collapse;font-size:18px}}
.dtable th{{
  text-align:left;padding:11px 16px;
  background:var(--s2);color:var(--t3);font-weight:700;
  font-size:16px;text-transform:uppercase;letter-spacing:.8px;
  border-bottom:1px solid var(--bd);border-top:1px solid var(--bd);
}}
.dtable td{{
  padding:13px 18px;border-bottom:1px solid var(--bd2);
  color:var(--t1);vertical-align:top;
}}
.dtable tbody tr:hover td{{background:var(--s2)}}
.mono{{font-family:var(--mono);font-size:17px;color:var(--t2)}}
.trunc{{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}

/* ─── KEY-VALUE GRID ─────────────────────────────────────────────── */
.kv-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;
          background:var(--bd);border:1px solid var(--bd)}}
@media(max-width:900px){{.kv-grid{{grid-template-columns:1fr 1fr}}}}
.kv{{
  display:flex;justify-content:space-between;align-items:center;
  padding:9px 14px;background:var(--s1);gap:12px;
}}
.k{{font-size:17px;color:var(--t3);font-weight:600;white-space:nowrap}}
.v{{font-family:var(--mono);font-size:17px;color:var(--t1);
    text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:55%}}

/* ─── CHARTS ─────────────────────────────────────────────────────── */
.chart-row{{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--bd);
            border:1px solid var(--bd);margin-bottom:1px}}
@media(max-width:900px){{.chart-row{{grid-template-columns:1fr}}}}
.ch-panel{{background:var(--s1);padding:16px}}
.ch-label{{font-size:15px;font-weight:700;text-transform:uppercase;
           letter-spacing:.8px;color:var(--t3);margin-bottom:12px}}
.ch-wrap{{position:relative;height:240px}}

/* ─── FLAGS ──────────────────────────────────────────────────────── */
.flag-row{{
  display:flex;align-items:flex-start;gap:10px;
  border-bottom:1px solid var(--bd2);padding:8px 0;transition:opacity .2s;
}}
.flag-row:last-child{{border-bottom:none}}
.flag-row.ack{{opacity:.45}}
.flag-row.ack .ftext{{text-decoration:line-through;color:var(--t3)}}
.fbadge{{
  font-size:15px;font-weight:800;letter-spacing:.8px;text-transform:uppercase;
  padding:6px 12px;text-align:center;flex-shrink:0;min-width:90px;
}}
.fbadge.CRITICAL{{background:#3a0b20;color:#ff7bba;border:1px solid #7a1744}}
.fbadge.HIGH{{background:#2d0f0f;color:var(--red);border:1px solid #5a1a1a}}
.fbadge.MEDIUM{{background:#2e2200;color:#e3b341;border:1px solid #6a4f00}}
.fbadge.LOW{{background:#0d1f3e;color:var(--blu);border:1px solid #1f4176}}
.ftext{{font-size:18px;color:var(--t1)}}
.fpath{{font-family:var(--mono);font-size:16px;color:var(--t3);margin-top:4px;word-break:break-all}}
.ack-btn{{
  flex-shrink:0;margin-left:auto;font-size:15px;font-weight:600;padding:6px 14px;
  border:1px solid #30363d;color:#484f58;background:transparent;cursor:pointer;
  white-space:nowrap;transition:.15s;
}}
.ack-btn:hover{{border-color:#3fb950;color:#3fb950}}
.flag-row.ack .ack-btn{{border-color:#30363d;color:#30363d}}
.flag-row.ack .ack-btn:hover{{border-color:#f85149;color:#f85149}}

/* ─── PACKAGES ───────────────────────────────────────────────────── */
.pkg-table{{width:100%;border-collapse:collapse;font-size:17px}}
.pkg-table td{{padding:7px 14px;border-bottom:1px solid var(--bd2);font-family:var(--mono)}}
.pkg-table tr:hover td{{background:var(--s2)}}
.pkg-3p{{color:var(--acc)}}

/* ─── HASH ───────────────────────────────────────────────────────── */
.hash-ok{{
  display:flex;align-items:center;gap:10px;
  padding:14px 18px;margin-bottom:14px;
  background:var(--s2);border-left:3px solid var(--grn);
  font-size:18px;
}}
.hash-row{{padding:12px 0;border-bottom:1px solid var(--bd2)}}
.hr-file{{font-size:17px;color:var(--t3);margin-bottom:3px}}
.hr-hash{{font-family:var(--mono);font-size:16px;color:var(--grn);word-break:break-all}}

/* ─── LOG ────────────────────────────────────────────────────────── */
.log-line{{
  display:flex;gap:10px;align-items:baseline;
  padding:8px 0;border-bottom:1px solid var(--bd2);font-size:17px;
}}
.log-ts{{font-family:var(--mono);color:var(--t3);flex-shrink:0;font-size:16px;width:170px}}
.log-msg{{color:var(--t2)}}

/* ─── TABS ───────────────────────────────────────────────────────── */
.tabs{{display:flex;border-bottom:1px solid var(--bd);margin-bottom:14px}}
.tab{{
  padding:12px 22px;cursor:pointer;font-size:17px;font-weight:600;
  color:var(--t3);border-bottom:2px solid transparent;margin-bottom:-1px;
  text-transform:uppercase;letter-spacing:.5px;transition:.12s;
}}
.tab:hover{{color:var(--t2)}}
.tab.active{{color:var(--acc);border-bottom-color:var(--acc)}}
.tab-pane{{display:none}}.tab-pane.active{{display:block}}

/* ─── CAT BADGE ──────────────────────────────────────────────────── */
.cbadge{{font-size:13px;font-weight:600;padding:2px 8px;
         background:var(--s2);border:1px solid var(--bd);color:var(--t2)}}

/* ─── SCROLLBOX ──────────────────────────────────────────────────── */
.scrollbox{{max-height:260px;overflow-y:auto}}

/* ─── EMPTY ──────────────────────────────────────────────────────── */
.empty{{color:var(--t3);font-size:18px;padding:22px 0;text-align:center}}

/* ─── FOOTER ─────────────────────────────────────────────────────── */
.footer{{
  border-top:1px solid var(--bd);margin-top:20px;padding:20px 32px;
  display:flex;align-items:center;justify-content:space-between;
  font-size:16px;color:var(--t3);
}}
.footer strong{{color:var(--t2)}}

/* ─── PRINT ──────────────────────────────────────────────────────── */
@media print{{
  body{{background:#fff;color:#000;font-size:11px}}
  .banner{{position:static;background:#f4f4f4;border-bottom:2px solid #000}}
  .brand-name,.brand-tag,.bm-val,.bm-label{{color:#000}}
  .bm-label{{color:#666}}
  .sidebar{{display:none}}
  .main{{padding:16px}}
  .metrics{{border-color:#ccc}}
  .metric{{border-color:#ccc}}
  .m-val,.m-label{{color:#000}}
  .m-sub{{color:#666}}
  .kv-grid{{background:#ccc}}
  .kv{{background:#fff}}
  .k{{color:#666}}.v{{color:#000}}
  .sec-title,.sec-num{{color:#333}}
  .dtable th{{background:#f0f0f0;color:#333}}
  .dtable td{{color:#000}}
  .fbadge.HIGH{{background:#fee;color:#900;border-color:#c00}}
  .fbadge.MEDIUM{{background:#ffe;color:#860;border-color:#ca0}}
  .fbadge.LOW{{background:#eef;color:#369;border-color:#369}}
  .hash-ok{{background:#f0fff0;border-color:#090}}
  canvas{{max-width:100%!important}}
}}
</style>
</head>
<body>

<!-- ═══ TOP BANNER ══════════════════════════════════════════════════════ -->
<div class="banner">
  <div class="banner-brand">
    <div>
      <div class="brand-name">Droid<em>Trace</em></div>
      <div class="brand-tag">Forensic Report</div>
    </div>
  </div>
  <div class="banner-meta">
    <div class="bm-item">
      <span class="bm-label">Case No.</span>
      <span class="bm-val">{case_number}</span>
    </div>
    <div class="bm-item">
      <span class="bm-label">Investigator</span>
      <span class="bm-val">{investigator}</span>
    </div>
    <div class="bm-item">
      <span class="bm-label">Acquired</span>
      <span class="bm-val">{acq_time[:19] if acq_time != 'N/A' else 'N/A'}</span>
    </div>
    <div class="bm-item">
      <span class="bm-label">Generated</span>
      <span class="bm-val">{gen_time}</span>
    </div>
    <div class="bm-item">
      <span class="bm-label">Algorithm</span>
      <span class="bm-val">SHA-256</span>
    </div>
  </div>
  <div class="banner-actions">
    <a href="{explorer_url}" target="_blank" class="btn-outline">
      <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14"></path></svg>
      Gallery
    </a>
    <a href="{explorer_url}?mode=explorer" target="_blank" class="btn-outline">
      <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>
      Files
    </a>
    <button class="btn-outline" onclick="window.print()">
      <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"></path></svg>
      Print
    </button>
  </div>
</div>

<div class="layout">

<!-- ═══ SIDEBAR TOC ═════════════════════════════════════════════════════ -->
<nav class="sidebar">
  <div class="toc-head">Contents</div>
  <a class="toc-link active" href="#s-case">Case Info</a>
  <a class="toc-link" href="#s-device">Device</a>
  <a class="toc-link" href="#s-summary">Summary</a>
  <a class="toc-link" href="#s-charts">Analysis</a>
  <a class="toc-link" href="#s-apps">App Insights</a>
  <div class="toc-sep"></div>
  <a class="toc-link" href="#s-packages">Packages</a>
  <a class="toc-link" href="#s-flags">Forensic Flags</a>
  <a class="toc-link" href="#s-iflags">Investigator Flags</a>
  <a class="toc-link" href="#s-files">Notable Files</a>
  <a class="toc-link" href="#s-hashes">Integrity</a>
  <a class="toc-link" href="#s-log">Acq. Log</a>
</nav>

<!-- ═══ MAIN ════════════════════════════════════════════════════════════ -->
<main class="main">

<!-- §1 Case Information -->
<section class="section" id="s-case">
  <div class="sec-hd">
    <span class="sec-num">01</span>
    <span class="sec-title">Case Information</span>
  </div>
  <div class="kv-grid">
    <div class="kv"><span class="k">Case Number</span><span class="v">{case_number}</span></div>
    <div class="kv"><span class="k">Investigator</span><span class="v">{investigator}</span></div>
    <div class="kv"><span class="k">Acquired At</span><span class="v">{acq_time[:19] if acq_time != 'N/A' else 'N/A'}</span></div>
    <div class="kv"><span class="k">Duration</span><span class="v">{acq_duration}s</span></div>
    <div class="kv"><span class="k">Report Generated</span><span class="v">{gen_time}</span></div>
    <div class="kv"><span class="k">Tool Version</span><span class="v">DroidTrace v1.0.0</span></div>
  </div>
  {f'<div style="margin-top:10px;padding:10px 14px;background:var(--s2);border-left:3px solid var(--acc);font-size:12px;color:var(--t1)"><span style="font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:1px;display:block;margin-bottom:4px;">Notes</span>{notes}</div>' if notes else ''}
</section>

<!-- §2 Device Information -->
<section class="section" id="s-coverage">
  <div class="sec-hd">
    <span class="sec-num">01A</span>
    <span class="sec-title">Acquisition Coverage</span>
  </div>
  {self._coverage_html()}
  <div style="margin-top:10px;padding:10px 14px;background:var(--s2);border-left:3px solid var(--acc);font-size:12px;color:var(--t2)">
    Non-root logical acquisition cannot access protected app-private data. Android 16 may block SMS and call-log access; DroidTrace records that status and supports manual import as evidence.
  </div>
</section>

<section class="section" id="s-device">
  <div class="sec-hd">
    <span class="sec-num">02</span>
    <span class="sec-title">Device Information</span>
  </div>
  <div class="kv-grid">
{self._info_rows()}
  </div>
</section>

<!-- §3 Evidence Summary -->
<section class="section" id="s-summary">
  <div class="sec-hd">
    <span class="sec-num">03</span>
    <span class="sec-title">Evidence Summary</span>
  </div>
  <div class="metrics">
    <div class="metric">
      <div class="m-val">{summary.get('total_files', 0):,}</div>
      <div class="m-label">Total Files</div>
      <div class="m-sub">Acquired artefacts</div>
    </div>
    <div class="metric">
      <div class="m-val">{summary.get('total_size_mb', 0):.1f}</div>
      <div class="m-label">Size (MB)</div>
      <div class="m-sub">{summary.get('total_size_gb', 0):.3f} GB</div>
    </div>
    <div class="metric">
      <div class="m-val">{self.analysis.get('recent_activity', {}).get('count', 0)}</div>
      <div class="m-label">Recent Files</div>
      <div class="m-sub">Modified last 7 days</div>
    </div>
    <div class="metric">
      <div class="m-val" style="color:{'var(--red)' if flag_count else 'var(--grn)'}">{flag_count}</div>
      <div class="m-label">Forensic Flags</div>
      <div class="m-sub">{'Issues detected' if flag_count else 'No issues'}</div>
    </div>
  </div>
</section>

<!-- §4 File Analysis -->
<section class="section" id="s-charts">
  <div class="sec-hd">
    <span class="sec-num">04</span>
    <span class="sec-title">File Analysis</span>
  </div>
  <div class="chart-row">
    <div class="ch-panel">
      <div class="ch-label">File Type Distribution</div>
      <div class="ch-wrap"><canvas id="pieChart"></canvas></div>
    </div>
    <div class="ch-panel">
      <div class="ch-label">Monthly Activity Timeline</div>
      <div class="ch-wrap"><canvas id="barChart"></canvas></div>
    </div>
  </div>
  <div style="background:var(--bd);padding:1px">
    <div class="ch-panel">
      <div class="ch-label">Storage by Category (MB)</div>
      <div class="ch-wrap" style="height:180px"><canvas id="sizeChart"></canvas></div>
    </div>
  </div>
</section>

<!-- §5 App Insights -->
<section class="section" id="s-apps">
  <div class="sec-hd">
    <span class="sec-num">05</span>
    <span class="sec-title">App Insights</span>
  </div>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--bd);border:1px solid var(--bd)">
{self._app_cards()}
  </div>
</section>

<!-- §6 Installed Packages -->
<section class="section" id="s-packages">
  <div class="sec-hd">
    <span class="sec-num">06</span>
    <span class="sec-title">Installed Packages</span>
    <span class="sec-count">{len(self.packages)} total</span>
  </div>
  <div class="scrollbox" style="border:1px solid var(--bd)">
    {self._packages_html()}
  </div>
</section>

<!-- §7 Forensic Flags -->
<section class="section" id="s-flags">
  <div class="sec-hd">
    <span class="sec-num">07</span>
    <span class="sec-title">Forensic Flags</span>
    <span class="sec-count" style="color:{'var(--red)' if flag_count else 'var(--grn)'}">{flag_count} {'flag' if flag_count == 1 else 'flags'}</span>
  </div>
  <div class="scrollbox" style="border:1px solid var(--bd);padding:8px 14px">
    {self._flags_html()}
  </div>
</section>

<!-- §8 Investigator Flags -->
<section class="section" id="s-iflags">
  <div class="sec-hd">
    <span class="sec-num">08</span>
    <span class="sec-title">Investigator File Flags</span>
    <span class="sec-count" style="color:{'var(--red)' if self.file_flags else 'var(--t3)'}">
      {len(self.file_flags)} {'flag' if len(self.file_flags) == 1 else 'flags'} marked
    </span>
  </div>
  <div class="scrollbox" style="border:1px solid var(--bd);padding:8px 14px">
    {self._investigator_flags_html()}
  </div>
</section>

<!-- §9 Notable Files -->
<section class="section" id="s-files">
  <div class="sec-hd">
    <span class="sec-num">09</span>
    <span class="sec-title">Notable Files</span>
    <span class="sec-count" style="margin-left:auto;display:flex;gap:8px;">
      <a href="{explorer_url}?view=large" target="_blank" class="btn-outline" style="font-size:10px;padding:3px 10px;">View All Large ↗</a>
      <a href="{explorer_url}?view=recent" target="_blank" class="btn-outline" style="font-size:10px;padding:3px 10px;">View All Recent ↗</a>
    </span>
  </div>
  <div class="tabs">
    <div class="tab active" onclick="switchTab(this,'large')">Large ({len(large)})</div>
    <div class="tab" onclick="switchTab(this,'recent')">Recent ({len(recent)})</div>
  </div>
  <div id="large" class="tab-pane active">{self._file_table(large, "No large files detected")}</div>
  <div id="recent" class="tab-pane">{self._file_table(recent, "No recent files detected")}</div>
</section>

<!-- §10 Integrity -->
<section class="section" id="s-hashes">
  <div class="sec-hd">
    <span class="sec-num">10</span>
    <span class="sec-title">SHA-256 Integrity Verification</span>
  </div>
  <div class="hash-ok">
    <svg width="14" height="14" fill="none" stroke="var(--grn)" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>
    <span><strong>Hash Manifest Active</strong> — {self.hash_data.get('total_files', 0)} file(s) hashed using SHA-256. Generated: {self.hash_data.get('generated_at', 'N/A')}</span>
  </div>
  {self._hash_samples()}
</section>

<!-- §11 Acquisition Log -->
<section class="section" id="s-log">
  <div class="sec-hd">
    <span class="sec-num">11</span>
    <span class="sec-title">Acquisition Log</span>
  </div>
  <div class="scrollbox" style="border:1px solid var(--bd);padding:8px 14px">
    {self._acq_log_html()}
  </div>
</section>

</main>
</div><!-- /layout -->

<footer class="footer">
  <span><strong>DroidTrace v1.0.0</strong> — Open-Source Mobile Forensic Toolkit</span>
  <span>LGU Final Year Project — Muhammad Fahad Khan (Fall-2022-072/B)</span>
</footer>

<script>
function switchTab(el, id) {{
  el.closest('.section').querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.closest('.section').querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(id).classList.add('active');
}}

// TOC active on scroll
const sections = document.querySelectorAll('.section[id]');
const links = document.querySelectorAll('.toc-link');
const obs = new IntersectionObserver(entries => {{
  entries.forEach(e => {{
    if (e.isIntersecting) {{
      links.forEach(l => l.classList.remove('active'));
      const a = document.querySelector('.toc-link[href="#' + e.target.id + '"]');
      if (a) a.classList.add('active');
    }}
  }});
}}, {{rootMargin:'-20% 0px -70% 0px'}});
sections.forEach(s => obs.observe(s));

Chart.defaults.color = '#484f58';
Chart.defaults.borderColor = '#21262d';
const PALETTE = ['#e3b341','#58a6ff','#f85149','#3fb950','#bc8cff','#f0883e','#39d353','#8b949e'];

new Chart(document.getElementById('pieChart'), {{
  type: 'doughnut',
  data: {{
    labels: {cat_labels},
    datasets: [{{data:{cat_counts},backgroundColor:PALETTE,borderWidth:2,borderColor:'#161b22',hoverOffset:4}}]
  }},
  options: {{
    responsive:true, maintainAspectRatio:false,
    plugins:{{legend:{{position:'right',labels:{{padding:12,font:{{size:11}},boxWidth:12}}}}}}
  }}
}});

new Chart(document.getElementById('barChart'), {{
  type: 'bar',
  data: {{
    labels: {tl_labels},
    datasets: [{{label:'Files',data:{tl_values},backgroundColor:'#e3b341',borderWidth:0,borderRadius:2}}]
  }},
  options: {{
    responsive:true,maintainAspectRatio:false,
    scales:{{
      y:{{beginAtZero:true,grid:{{color:'#21262d'}}}},
      x:{{grid:{{display:false}},ticks:{{maxRotation:45,font:{{size:10}}}}}}
    }},
    plugins:{{legend:{{display:false}}}}
  }}
}});

new Chart(document.getElementById('sizeChart'), {{
  type: 'bar',
  data: {{
    labels: {cat_labels},
    datasets: [{{label:'MB',data:{cat_sizes},backgroundColor:PALETTE,borderWidth:0,borderRadius:2}}]
  }},
  options: {{
    indexAxis:'y',responsive:true,maintainAspectRatio:false,
    scales:{{
      x:{{beginAtZero:true,grid:{{color:'#21262d'}},title:{{display:true,text:'MB',color:'#484f58',font:{{size:10}}}}}},
      y:{{grid:{{display:false}}}}
    }},
    plugins:{{legend:{{display:false}}}}
  }}
}});

// ── Live flag acknowledgments ────────────────────────────────────────────────
const _DEVICE  = "{_device}";
const _SESSION = "{_session}";
let _acks = {{}};

async function loadAcks() {{
  try {{
    const r = await fetch(`/api/flags/${{_DEVICE}}/${{_SESSION}}/acknowledgments`);
    const d = await r.json();
    _acks = d.acknowledgments || {{}};
    applyAcks();
  }} catch(e) {{}}
}}

function applyAcks() {{
  document.querySelectorAll('.flag-row[data-fkey]').forEach(row => {{
    const key = row.dataset.fkey;
    if (_acks[key]) {{
      row.classList.add('ack');
      row.querySelector('.ack-btn').textContent = '↺ Reopen';
    }} else {{
      row.classList.remove('ack');
      row.querySelector('.ack-btn').textContent = '✓ Reviewed';
    }}
  }});
}}

async function toggleAck(btn, flagKey) {{
  const isAcked = !!_acks[flagKey];
  if (isAcked) {{
    await fetch(`/api/flags/${{_DEVICE}}/${{_SESSION}}/acknowledge?flag_key=${{encodeURIComponent(flagKey)}}`, {{method:'DELETE'}});
    delete _acks[flagKey];
  }} else {{
    const by = ''; // could prompt for investigator name
    await fetch(`/api/flags/${{_DEVICE}}/${{_SESSION}}/acknowledge`, {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{flag_key: flagKey, acknowledged_by: by, note: ''}})
    }});
    _acks[flagKey] = {{flag_key: flagKey}};
  }}
  applyAcks();
}}

loadAcks();
if (window.gsap) {{
  gsap.from('.banner', {{y:-16, opacity:0, duration:.4, ease:'power2.out'}});
  gsap.from('.sidebar,.section', {{y:14, opacity:0, duration:.5, stagger:.045, delay:.08, ease:'power2.out'}});
  gsap.from('.metric', {{y:10, opacity:0, duration:.35, stagger:.04, delay:.18, ease:'power2.out'}});
}}
</script>
</body>
</html>"""

        path = self.reports_dir / "dashboard.html"
        path.write_text(html, encoding="utf-8")
        print(f"[+] HTML dashboard -> {path}")
        return path

    # ------------------------------------------------------------------
    # Master entry point
    # ------------------------------------------------------------------

    def generate_all(self) -> dict:
        """Load data and produce all three report formats."""
        print(f"\n{'='*60}")
        print("  DroidTrace  —  Reporting Module")
        print(f"{'='*60}\n")

        self.load_data()

        if not self.analysis:
            print("[-] No analysis data found. Run 'analyze' first.")
            return {}

        self._status_cb("Generating JSON report...")
        json_path = self.generate_json()
        self._status_cb("Generating CSV report...")
        csv_path  = self.generate_csv()
        self._status_cb("Generating HTML dashboard...")
        html_path = self.generate_html()

        print(f"\n[+] All reports written to {self.reports_dir}/")
        return {
            "json":      str(json_path),
            "csv":       str(csv_path),
            "html":      str(html_path),
        }

