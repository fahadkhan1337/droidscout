"""
reporting.py — DroidScout
Generates JSON, CSV, and an interactive HTML dashboard from analysis data.
"""

import csv
import json
from datetime import datetime
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
        report = {
            "report_metadata": {
                "tool":           "DroidScout v1.0.0",
                "generated_at":   datetime.now().isoformat(),
                "report_type":    "Mobile Forensic Analysis Report",
                "project":        "Open-Source Mobile Forensic Toolkit — LGU FYP",
                "student":        "Muhammad Fahad Khan (Fall-2022-072/B)",
            },
            "device_information": self.device_info,
            "evidence_summary":   self.analysis.get("summary", {}),
            "file_categories":    self.analysis.get("file_categories", {}),
            "analysis": {
                "large_files":      self.analysis.get("large_files", []),
                "recent_activity":  self.analysis.get("recent_activity", {}),
                "app_artifacts":    self.analysis.get("app_artifacts", {}),
                "timeline":         self.analysis.get("timeline", {}),
                "forensic_flags":   self.analysis.get("forensic_flags", []),
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
                  "modified_time", "sha256", "path"]

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
            return '<div class="info-row"><span class="ik">Status</span><span class="iv">No device info available</span></div>'
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
            rows.append(
                f'<div class="info-row">'
                f'<span class="ik">{label}</span>'
                f'<span class="iv" title="{v}">{v}</span>'
                f'</div>'
            )
        return "\n".join(rows)

    def _app_cards(self) -> str:
        apps_cfg = [
            ("WhatsApp", "wa",  "#25D366"),
            ("Telegram",  "tg",  "#2AABEE"),
            ("Signal",    "sg",  "#3A76F0"),
            ("Instagram", "ig",  "#E1306C"),
        ]
        app_data = self.analysis.get("app_artifacts", {})
        cards = []
        for name, css, colour in apps_cfg:
            d = app_data.get(name)
            if d:
                breakdown = "".join(
                    f'<div class="as"><span>{c}</span><span>{n}</span></div>'
                    for c, n in d.get("file_breakdown", {}).items()
                )
                inner = (
                    f'<div class="as"><span>Total Files</span><span>{d["total_files"]}</span></div>'
                    f'<div class="as"><span>Total Size</span><span>{d["total_size_mb"]} MB</span></div>'
                    f'{breakdown}'
                )
            else:
                inner = '<div class="app-empty">Not found / no media</div>'

            cards.append(
                f'<div class="app-card" style="--ac:{colour}">'
                f'<div class="app-name">{name}</div>{inner}</div>'
            )
        return "\n".join(cards)

    def _flags_html(self) -> str:
        flags = self.analysis.get("forensic_flags", [])
        if not flags:
            return '<div class="empty">No forensic flags detected</div>'

        sev_cfg = {
            "HIGH":   {"color": "#f85149", "bg": "rgba(248,81,73,.08)",   "bd": "rgba(248,81,73,.25)"},
            "MEDIUM": {"color": "#d29922", "bg": "rgba(210,153,34,.08)",  "bd": "rgba(210,153,34,.25)"},
            "LOW":    {"color": "#58a6ff", "bg": "rgba(88,166,255,.08)",  "bd": "rgba(88,166,255,.25)"},
        }

        # Group by severity
        grouped: dict = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for fl in flags:
            sev = fl.get("severity", "LOW")
            grouped.setdefault(sev, []).append(fl)

        sections = []
        for sev in ("HIGH", "MEDIUM", "LOW"):
            group = grouped.get(sev, [])
            if not group:
                continue
            cfg = sev_cfg.get(sev, sev_cfg["LOW"])
            rows = []
            for fl in group:
                file_part = (
                    f'<span style="font-family:monospace;font-size:10px;color:#8b949e;'
                    f'margin-left:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'
                    f'max-width:260px;display:inline-block;vertical-align:middle" title="{fl.get("file","")}">'
                    f'— {fl["file"].split("/")[-1] if fl.get("file") else ""}</span>'
                ) if fl.get("file") else ""
                rows.append(
                    f'<div style="display:flex;align-items:baseline;gap:8px;padding:5px 10px;'
                    f'border-bottom:1px solid {cfg["bd"]}22;font-size:12px">'
                    f'<span style="color:{cfg["color"]};font-weight:700;font-size:10px;'
                    f'white-space:nowrap;min-width:140px">{fl.get("type","")}</span>'
                    f'<span style="color:#8b949e;flex:1">{fl.get("description","")}</span>'
                    f'{file_part}</div>'
                )
            header = (
                f'<div style="display:flex;align-items:center;gap:8px;padding:7px 10px;'
                f'background:{cfg["bg"]};border-bottom:1px solid {cfg["bd"]}">'
                f'<span style="background:{cfg["color"]};color:#fff;font-size:10px;font-weight:800;'
                f'padding:2px 8px;border-radius:4px">{sev}</span>'
                f'<span style="color:{cfg["color"]};font-weight:600;font-size:12px">'
                f'{len(group)} flag{"s" if len(group)>1 else ""}</span></div>'
            )
            sections.append(
                f'<div style="border:1px solid {cfg["bd"]};border-radius:6px;'
                f'overflow:hidden;margin-bottom:8px">'
                f'{header}{"".join(rows)}</div>'
            )
        return "\n".join(sections)

    def _file_table(self, files: list, empty: str = "No files") -> str:
        if not files:
            return f'<div class="empty">{empty}</div>'
        rows = "".join(
            f'<tr><td>{f.get("name","")}</td>'
            f'<td><span class="cat-badge cat-{f.get("category","other")}">'
            f'{f.get("category","")}</span></td>'
            f'<td>{f.get("size_mb",0):.2f} MB</td>'
            f'<td>{f.get("modified_time","")[:19]}</td>'
            f'<td class="pcell" title="{f.get("path","")}">{f.get("path","")}</td></tr>'
            for f in files
        )
        return (
            '<table class="ftable"><thead><tr>'
            '<th>Filename</th><th>Category</th><th>Size</th>'
            '<th>Modified</th><th>Path</th>'
            '</tr></thead><tbody>' + rows + '</tbody></table>'
        )

    def _packages_html(self) -> str:
        if not self.packages:
            return '<div class="empty">No package list available</div>'
        # Color third-party packages differently (not com.android / com.google / com.samsung etc.)
        system_prefixes = ("com.android", "com.google", "com.samsung", "com.qualcomm",
                           "com.mediatek", "com.miui", "android", "com.huawei",
                           "com.lge", "com.htc", "com.sony", "com.oppo", "com.vivo")
        items = []
        for pkg in self.packages:
            is_system = pkg.startswith(system_prefixes)
            color = "#8b949e" if is_system else "#58a6ff"
            items.append(
                f'<div style="font-family:monospace;font-size:11px;color:{color};'
                f'padding:2px 0;border-bottom:1px solid #21262d22;white-space:nowrap;'
                f'overflow:hidden;text-overflow:ellipsis" title="{pkg}">{pkg}</div>'
            )
        return "\n".join(items)

    def _acq_log_html(self) -> str:
        log = self.manifest.get("log", [])
        if not log:
            return '<div class="empty">No acquisition log available</div>'
        color_map = {"SUCCESS": "#3fb950", "WARNING": "#d29922", "ERROR": "#f85149", "INFO": "#8b949e"}
        rows = []
        for entry in log:
            level = entry.get("level", "INFO")
            color = color_map.get(level, "#8b949e")
            ts = entry.get("timestamp", "")[:19]
            msg = entry.get("message", "")
            rows.append(
                f'<div style="display:flex;gap:12px;padding:5px 0;border-bottom:1px solid #21262d;font-size:12px">'
                f'<span style="color:#444d56;white-space:nowrap;flex-shrink:0">{ts}</span>'
                f'<span style="color:{color};font-weight:700;flex-shrink:0;min-width:55px">{level}</span>'
                f'<span style="color:#e6edf3">{msg}</span></div>'
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

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>DroidScout — Forensic Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg0:#0d1117;--bg1:#161b22;--bg2:#1c2128;--bd:#30363d;
  --t1:#e6edf3;--t2:#8b949e;
  --blue:#58a6ff;--green:#3fb950;--yellow:#d29922;
  --red:#f85149;--purple:#bc8cff;--orange:#f0883e;
  --teal:#39d353;
}}
body{{background:var(--bg0);color:var(--t1);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px}}

/* ── Header ── */
.hdr{{background:var(--bg1);border-bottom:1px solid var(--bd);padding:14px 32px;
      display:flex;align-items:center;justify-content:space-between;
      position:sticky;top:0;z-index:99}}
.logo{{font-size:20px;font-weight:800;color:var(--blue);letter-spacing:-0.5px}}
.logo span{{color:var(--t1)}}
.hdr-badge{{background:rgba(88,166,255,.15);color:var(--blue);
            border:1px solid rgba(88,166,255,.3);padding:3px 12px;
            border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.5px}}
.hdr-meta{{color:var(--t2);font-size:12px;text-align:right;line-height:1.6}}

/* ── Layout ── */
.wrap{{max-width:1440px;margin:0 auto;padding:28px 32px}}
.sec-title{{font-size:11px;font-weight:700;color:var(--t2);
            text-transform:uppercase;letter-spacing:1.2px;
            margin-bottom:14px;display:flex;align-items:center;gap:8px}}
.sec-title::before{{content:'';display:inline-block;width:3px;height:14px;
                    background:var(--blue);border-radius:2px}}
.mb{{margin-bottom:24px}}

/* ── Cards ── */
.card{{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;padding:20px}}
.card-title{{font-size:12px;color:var(--t2);margin-bottom:6px;font-weight:500}}
.card-val{{font-size:30px;font-weight:800;color:var(--t1)}}
.card-sub{{font-size:11px;color:var(--t2);margin-top:3px}}

/* ── Stat grid ── */
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}}
@media(max-width:900px){{.stats{{grid-template-columns:repeat(2,1fr)}}}}

/* ── Charts ── */
.charts{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
@media(max-width:900px){{.charts{{grid-template-columns:1fr}}}}
.ch-wrap{{position:relative;height:300px}}

/* ── Device info grid ── */
.info-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}
@media(max-width:900px){{.info-grid{{grid-template-columns:1fr 1fr}}}}
.info-row{{display:flex;justify-content:space-between;align-items:center;
           padding:10px 14px;background:var(--bg1);border:1px solid var(--bd);
           border-radius:6px}}
.ik{{color:var(--t2);font-size:12px;font-weight:500;white-space:nowrap}}
.iv{{color:var(--t1);font-size:12px;font-family:monospace;text-align:right;
     max-width:55%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}

/* ── App cards ── */
.app-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}}
@media(max-width:900px){{.app-grid{{grid-template-columns:repeat(2,1fr)}}}}
.app-card{{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;
           padding:18px;position:relative;overflow:hidden}}
.app-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;
                   background:var(--ac,#58a6ff)}}
.app-name{{font-size:15px;font-weight:700;margin-bottom:12px}}
.as{{display:flex;justify-content:space-between;padding:5px 0;font-size:12px;
     color:var(--t2);border-bottom:1px solid var(--bd)}}
.as span:last-child{{color:var(--t1);font-weight:600}}
.app-empty{{color:var(--t2);font-size:12px;font-style:italic}}

/* ── Flags ── */
.flag{{display:flex;align-items:flex-start;gap:12px;padding:12px 16px;
       border-radius:6px;margin-bottom:8px;border:1px solid}}
.flag.HIGH{{background:rgba(248,81,73,.08);border-color:rgba(248,81,73,.3)}}
.flag.MEDIUM{{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3)}}
.flag.LOW{{background:rgba(88,166,255,.08);border-color:rgba(88,166,255,.3)}}
.fbadge{{font-size:10px;font-weight:800;padding:3px 8px;border-radius:4px;
         white-space:nowrap;flex-shrink:0;margin-top:2px}}
.flag.HIGH .fbadge{{background:var(--red);color:#fff}}
.flag.MEDIUM .fbadge{{background:var(--yellow);color:#000}}
.flag.LOW .fbadge{{background:var(--blue);color:#000}}
.fcontent{{flex:1}}
.ftype{{font-weight:700;font-size:13px;margin-bottom:2px}}
.fdesc{{color:var(--t2);font-size:12px}}
.flag-file{{color:var(--blue);font-size:11px;font-family:monospace;
            margin-top:4px;word-break:break-all}}

/* ── File table ── */
.ftable{{width:100%;border-collapse:collapse;font-size:12px}}
.ftable th{{text-align:left;padding:10px 12px;background:var(--bg1);
            color:var(--t2);font-weight:600;border-bottom:1px solid var(--bd)}}
.ftable td{{padding:8px 12px;border-bottom:1px solid var(--bd)}}
.ftable tr:hover td{{background:rgba(255,255,255,.02)}}
.pcell{{font-family:monospace;color:var(--t2);max-width:280px;
        overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}

/* ── Category badges ── */
.cat-badge{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.cat-images{{background:rgba(88,166,255,.2);color:var(--blue)}}
.cat-videos{{background:rgba(248,81,73,.2);color:var(--red)}}
.cat-audio{{background:rgba(210,153,34,.2);color:var(--yellow)}}
.cat-documents{{background:rgba(63,185,80,.2);color:var(--green)}}
.cat-archives{{background:rgba(188,140,255,.2);color:var(--purple)}}
.cat-databases{{background:rgba(240,136,62,.2);color:var(--orange)}}
.cat-apk{{background:rgba(57,211,83,.2);color:var(--teal)}}
.cat-other{{background:rgba(139,148,158,.2);color:var(--t2)}}

/* ── Tabs ── */
.tabs{{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--bd)}}
.tab{{padding:8px 18px;cursor:pointer;font-size:13px;color:var(--t2);
      border-bottom:2px solid transparent;margin-bottom:-1px;transition:.15s}}
.tab.active{{color:var(--blue);border-bottom-color:var(--blue);font-weight:600}}
.tab-pane{{display:none}}.tab-pane.active{{display:block}}

/* ── Hash section ── */
.hash-ok{{display:flex;align-items:center;gap:10px;padding:12px 16px;
          background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.3);
          border-radius:6px;margin-bottom:14px}}
.hdot{{width:10px;height:10px;border-radius:50%;background:var(--green);flex-shrink:0}}
.hash-row{{padding:10px 0;border-bottom:1px solid var(--bd)}}
.hr-file{{font-size:12px;color:var(--t2);margin-bottom:4px}}
.hr-hash{{font-family:'Courier New',monospace;font-size:12px;color:var(--green);word-break:break-all}}

/* ── Misc ── */
.empty{{color:var(--t2);font-style:italic;padding:20px 0;text-align:center}}
.footer{{text-align:center;padding:32px;color:var(--t2);font-size:12px;
         border-top:1px solid var(--bd);margin-top:32px}}
/* ── Print ── */
@media print{{
  body{{background:#fff;color:#000}}
  .hdr{{position:static;background:#f5f5f5;border-bottom:2px solid #000}}
  .logo{{color:#000}}.logo span{{color:#333}}
  .hdr-badge,.hdr-meta{{color:#333}}
  .card,.info-row,.app-card{{background:#fff;border:1px solid #ccc}}
  .card-val,.card-title,.ik,.iv,.app-name,.ftype{{color:#000}}
  .fdesc,.card-sub,.t2{{color:#555}}
  .flag.HIGH{{background:#fff0ef;border-color:#c00}}
  .flag.MEDIUM{{background:#fffbea;border-color:#a66}}
  .flag.LOW{{background:#f0f8ff;border-color:#369}}
  canvas{{max-width:100%!important}}
  .sec-title::before{{background:#000}}
  .sec-title{{color:#000}}
}}
</style>
</head>
<body>

<!-- ═══ HEADER ═══════════════════════════════════════════════════════════ -->
<div class="hdr">
  <div style="display:flex;align-items:center;gap:14px">
    <div class="logo">Droid<span>Scout</span></div>
    <div class="hdr-badge">FORENSIC REPORT</div>
  </div>
  <div style="display:flex;align-items:center;gap:10px">
    <a href="{explorer_url}" target="_blank"
       style="display:inline-flex;align-items:center;gap:6px;background:rgba(88,166,255,.12);color:var(--blue);
              border:1px solid rgba(88,166,255,.3);padding:6px 14px;border-radius:6px;
              font-size:12px;font-weight:600;text-decoration:none;transition:.15s;"
       onmouseover="this.style.background='rgba(88,166,255,.25)'" onmouseout="this.style.background='rgba(88,166,255,.12)'">
      <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
      Gallery
    </a>
    <a href="{explorer_url}?mode=explorer" target="_blank"
       style="display:inline-flex;align-items:center;gap:6px;background:rgba(63,185,80,.1);color:#3fb950;
              border:1px solid rgba(63,185,80,.3);padding:6px 14px;border-radius:6px;
              font-size:12px;font-weight:600;text-decoration:none;transition:.15s;"
       onmouseover="this.style.background='rgba(63,185,80,.22)'" onmouseout="this.style.background='rgba(63,185,80,.1)'">
      <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>
      File Explorer
    </a>
    <div class="hdr-meta" style="text-align:right">
      Generated: {gen_time}<br>
      Tool: DroidScout v1.0.0 &nbsp;|&nbsp; Algorithm: SHA-256
    </div>
  </div>
</div>

<div class="wrap">

<!-- ═══ CASE METADATA ════════════════════════════════════════════════════ -->
<div class="sec-title">Case Information</div>
<div class="info-grid mb" style="grid-template-columns:repeat(3,1fr)">
  <div class="info-row"><span class="ik">Case Number</span><span class="iv">{case_number}</span></div>
  <div class="info-row"><span class="ik">Investigator</span><span class="iv">{investigator}</span></div>
  <div class="info-row"><span class="ik">Acquired At</span><span class="iv">{acq_time[:19] if acq_time != 'N/A' else 'N/A'}</span></div>
  <div class="info-row"><span class="ik">Duration</span><span class="iv">{acq_duration}s</span></div>
  <div class="info-row"><span class="ik">Generated At</span><span class="iv">{gen_time}</span></div>
  <div class="info-row"><span class="ik">Tool</span><span class="iv">DroidScout v1.0.0</span></div>
</div>
{f'<div class="card mb" style="background:rgba(88,166,255,.05);border-color:rgba(88,166,255,.2)"><div class="card-title">Case Notes</div><div style="font-size:13px;color:#e6edf3;margin-top:4px">{notes}</div></div>' if notes else ''}

<!-- ═══ DEVICE INFO ══════════════════════════════════════════════════════ -->
<div class="sec-title">Device Information</div>
<div class="info-grid mb">
{self._info_rows()}
</div>

<!-- ═══ EVIDENCE SUMMARY ═════════════════════════════════════════════════ -->
<div class="sec-title">Evidence Summary</div>
<div class="stats mb">
  <div class="card">
    <div class="card-title">Total Files</div>
    <div class="card-val">{summary.get('total_files', 0):,}</div>
    <div class="card-sub">Acquired artefacts</div>
  </div>
  <div class="card">
    <div class="card-title">Total Size</div>
    <div class="card-val">{summary.get('total_size_mb', 0):.1f} <span style="font-size:16px;font-weight:400">MB</span></div>
    <div class="card-sub">{summary.get('total_size_gb', 0):.3f} GB</div>
  </div>
  <div class="card">
    <div class="card-title">Recent Files</div>
    <div class="card-val">{self.analysis.get('recent_activity', {}).get('count', 0)}</div>
    <div class="card-sub">Modified last 7 days</div>
  </div>
  <div class="card">
    <div class="card-title">Forensic Flags</div>
    <div class="card-val" style="color:{flag_color}">{flag_count}</div>
    <div class="card-sub">{'Issues detected' if flag_count else 'Clean'}</div>
  </div>
</div>

<!-- ═══ CHARTS ═══════════════════════════════════════════════════════════ -->
<div class="sec-title">File Type Distribution &amp; Activity Timeline</div>
<div class="charts mb">
  <div class="card">
    <div class="card-title">File Types — Count</div>
    <div class="ch-wrap"><canvas id="pieChart"></canvas></div>
  </div>
  <div class="card">
    <div class="card-title">Monthly Activity Timeline</div>
    <div class="ch-wrap"><canvas id="barChart"></canvas></div>
  </div>
</div>

<!-- ═══ SIZE BREAKDOWN ═══════════════════════════════════════════════════ -->
<div class="sec-title">Storage by Category</div>
<div class="card mb">
  <div class="ch-wrap" style="height:220px"><canvas id="sizeChart"></canvas></div>
</div>

<!-- ═══ APP INSIGHTS ═════════════════════════════════════════════════════ -->
<div class="sec-title">App Insights</div>
<div class="app-grid mb">
{self._app_cards()}
</div>

<!-- ═══ INSTALLED PACKAGES ═══════════════════════════════════════════════ -->
<div class="sec-title">Installed Packages ({len(self.packages)})</div>
<div class="card mb" style="padding:0;overflow:hidden">
  <div style="max-height:220px;overflow-y:auto;padding:10px 14px">
    {self._packages_html()}
  </div>
</div>

<!-- ═══ FORENSIC FLAGS ═══════════════════════════════════════════════════ -->
<div class="sec-title">Forensic Flags ({flag_count})</div>
<div class="card mb" style="padding:0;overflow:hidden">
  <div style="max-height:280px;overflow-y:auto;padding:10px">
    {self._flags_html()}
  </div>
</div>

<!-- ═══ FILE TABLES ══════════════════════════════════════════════════════ -->
<div class="sec-title">Notable Files</div>
<div class="card mb">
  <div class="tabs">
    <div class="tab active" onclick="tab(this,'large')">Large Files ({len(large)})</div>
    <div class="tab" onclick="tab(this,'recent')">Recent Activity ({len(recent)})</div>
  </div>
  <div id="large" class="tab-pane active">
    {self._file_table(large, "No large files detected")}
  </div>
  <div id="recent" class="tab-pane">
    {self._file_table(recent, "No recent files detected")}
  </div>
</div>

<!-- ═══ INTEGRITY ════════════════════════════════════════════════════════ -->
<div class="sec-title">SHA-256 Integrity Verification</div>
<div class="card mb">
  <div class="hash-ok">
    <div class="hdot"></div>
    <div>
      <strong>Hash Manifest Active</strong> —
      {self.hash_data.get('total_files', 0)} file(s) hashed using SHA-256.
      Manifest generated: {self.hash_data.get('generated_at', 'N/A')}
    </div>
  </div>
  <div class="card-title" style="margin-bottom:10px">Sample Hash Records</div>
  {self._hash_samples()}
</div>

<!-- ═══ ACQUISITION LOG ══════════════════════════════════════════════════ -->
<div class="sec-title">Acquisition Log</div>
<div class="card mb" style="max-height:320px;overflow-y:auto">
  {self._acq_log_html()}
</div>

</div><!-- /wrap -->

<div class="footer">
  DroidScout v1.0.0 &nbsp;·&nbsp; Open-Source Mobile Forensic Toolkit &nbsp;·&nbsp;
  LGU Final Year Project — Muhammad Fahad Khan (Fall-2022-072/B)
</div>

<script>
// Tab switching
function tab(el, id) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(id).classList.add('active');
}}

// Chart.js global defaults
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';

const PALETTE = [
  '#58a6ff','#f85149','#d29922','#3fb950',
  '#bc8cff','#f0883e','#39d353','#8b949e'
];

// Pie — file type count
new Chart(document.getElementById('pieChart'), {{
  type: 'doughnut',
  data: {{
    labels: {cat_labels},
    datasets: [{{
      data: {cat_counts},
      backgroundColor: PALETTE,
      borderWidth: 2,
      borderColor: '#1c2128',
      hoverOffset: 6,
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{
      legend: {{
        position: 'right',
        labels: {{ padding: 14, font: {{ size: 12 }}, boxWidth: 14 }}
      }}
    }}
  }}
}});

// Bar — monthly timeline
new Chart(document.getElementById('barChart'), {{
  type: 'bar',
  data: {{
    labels: {tl_labels},
    datasets: [{{
      label: 'Files Modified',
      data: {tl_values},
      backgroundColor: 'rgba(88,166,255,0.55)',
      borderColor: '#58a6ff',
      borderWidth: 1,
      borderRadius: 4,
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      y: {{ beginAtZero: true, grid: {{ color: '#21262d' }} }},
      x: {{ grid: {{ color: '#21262d' }}, ticks: {{ maxRotation: 45, font: {{ size: 11 }} }} }}
    }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});

// Horizontal bar — storage by category (MB)
new Chart(document.getElementById('sizeChart'), {{
  type: 'bar',
  data: {{
    labels: {cat_labels},
    datasets: [{{
      label: 'Size (MB)',
      data: {cat_sizes},
      backgroundColor: PALETTE,
      borderWidth: 0,
      borderRadius: 4,
    }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ beginAtZero: true, grid: {{ color: '#21262d' }},
            title: {{ display: true, text: 'MB', color: '#8b949e' }} }},
      y: {{ grid: {{ color: '#21262d' }} }}
    }},
    plugins: {{ legend: {{ display: false }} }}
  }}
}});
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
        print("  DroidScout  —  Reporting Module")
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
