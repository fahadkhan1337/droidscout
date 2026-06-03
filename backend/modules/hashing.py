"""
hashing.py — DroidScout
SHA-256 integrity verification for all acquired evidence.
Generates both a machine-readable JSON manifest and a human-readable .txt list
(compatible with sha256sum -c for external verification).
"""

import hashlib
import json
import time
from datetime import datetime
from pathlib import Path

try:
    from tqdm import tqdm
    _TQDM = True
except ImportError:
    _TQDM = False


class HashingModule:
    """
    Computes and verifies SHA-256 hashes for forensic chain-of-custody.

    Two outputs are always produced:
    - hashes/hashes.json  — structured manifest (tool-readable)
    - hashes/hashes.txt   — sha256sum-compatible list (human/tool-verifiable)
    """

    CHUNK = 65536  # 64 KB read chunks for memory-efficient hashing

    def __init__(self, output_dir: str = "output", status_callback=None):
        self.output_dir = Path(output_dir)
        self.hashes_dir = self.output_dir / "hashes"
        self.hashes_dir.mkdir(parents=True, exist_ok=True)
        self._status_cb = status_callback or (lambda msg: None)

    # ------------------------------------------------------------------
    # Core hashing
    # ------------------------------------------------------------------

    def hash_file(self, path: Path) -> str:
        """
        Compute SHA-256 digest of a single file using chunked reads.
        Returns a hex string, or 'ERROR:<reason>' on failure.
        """
        sha = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(self.CHUNK), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except (OSError, IOError) as exc:
            return f"ERROR:{exc}"

    def hash_directory(self, root: Path) -> dict:
        """
        Recursively hash all files under *root*.

        Returns
        -------
        dict mapping relative-path strings → {sha256, size_bytes, hashed_at}
        """
        files = [p for p in root.rglob("*") if p.is_file()]
        iterator = tqdm(files, desc="  Hashing files", unit="file") if _TQDM else files
        result = {}
        for fp in iterator:
            rel = str(fp.relative_to(root))
            result[rel] = {
                "sha256":     self.hash_file(fp),
                "size_bytes": fp.stat().st_size,
                "hashed_at":  datetime.now().isoformat(),
            }
        return result

    # ------------------------------------------------------------------
    # Evidence hashing (main entry point)
    # ------------------------------------------------------------------

    def hash_evidence(self, evidence_dir: str = None) -> dict:
        """
        Hash all files in the evidence directory and write manifests.

        Parameters
        ----------
        evidence_dir : optional override; defaults to output/evidence/

        Returns
        -------
        Full manifest dict
        """
        root = Path(evidence_dir) if evidence_dir else self.output_dir / "evidence"

        print(f"\n{'='*60}")
        print("  DroidScout  —  Hashing Module")
        print(f"{'='*60}")
        print(f"\n[>] Computing SHA-256 for all files in {root} ...")

        if not root.exists():
            print("[-] Evidence directory not found. Run 'acquire' first.")
            return {}

        t0     = time.time()
        self._status_cb(f"Hashing files in {root.name}/...")
        hashes = self.hash_directory(root)
        elapsed = round(time.time() - t0, 2)

        manifest = {
            "tool":            "DroidScout v1.0.0",
            "generated_at":    datetime.now().isoformat(),
            "algorithm":       "SHA-256",
            "evidence_root":   str(root),
            "total_files":     len(hashes),
            "duration_seconds": elapsed,
            "hashes":          hashes,
        }

        # JSON manifest
        json_path = self.hashes_dir / "hashes.json"
        json_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # sha256sum-compatible .txt
        txt_path = self.hashes_dir / "hashes.txt"
        lines = [
            "# DroidScout SHA-256 Hash Manifest",
            f"# Generated : {manifest['generated_at']}",
            f"# Files     : {manifest['total_files']}",
            f"# Algorithm : {manifest['algorithm']}",
            "",
        ]
        for rel_path, data in hashes.items():
            lines.append(f"{data['sha256']}  {rel_path}")
        txt_path.write_text("\n".join(lines), encoding="utf-8")

        print(f"\n[+] Hashed {len(hashes)} file(s) in {elapsed}s")
        print(f"[+] JSON manifest : {json_path}")
        print(f"[+] TXT list      : {txt_path}")

        return manifest

    # ------------------------------------------------------------------
    # Integrity verification
    # ------------------------------------------------------------------

    def verify_integrity(self, manifest_path: str = None) -> dict:
        """
        Re-hash evidence files and compare against stored manifest.

        Returns
        -------
        dict with keys 'passed', 'failed', 'missing'
        """
        mpath = Path(manifest_path) if manifest_path else self.hashes_dir / "hashes.json"

        if not mpath.exists():
            print("[-] Hash manifest not found. Run 'acquire' (which calls hashing) first.")
            return {}

        manifest = json.loads(mpath.read_text(encoding="utf-8"))
        root     = Path(manifest["evidence_root"])
        stored   = manifest["hashes"]

        print(f"\n[>] Verifying {len(stored)} file(s) against stored manifest ...")

        results = {"passed": [], "failed": [], "missing": []}

        iterator = (
            tqdm(stored.items(), desc="  Verifying", unit="file")
            if _TQDM else stored.items()
        )

        for rel_path, data in iterator:
            full = root / rel_path
            if not full.exists():
                results["missing"].append(rel_path)
                continue
            current = self.hash_file(full)
            if current == data["sha256"]:
                results["passed"].append(rel_path)
            else:
                results["failed"].append({
                    "path":     rel_path,
                    "expected": data["sha256"],
                    "found":    current,
                })

        print(f"\n[+] Verification complete")
        print(f"    PASS    : {len(results['passed'])}")
        print(f"    FAIL    : {len(results['failed'])}")
        print(f"    MISSING : {len(results['missing'])}")

        if results["failed"]:
            print("\n[!] INTEGRITY VIOLATION — the following files have changed:")
            for f in results["failed"]:
                print(f"    {f['path']}")
                print(f"      expected : {f['expected']}")
                print(f"      found    : {f['found']}")

        return results
