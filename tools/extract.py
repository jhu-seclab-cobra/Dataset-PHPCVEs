#!/usr/bin/env python3
"""Extract PHPCVEs source archives into cves/<CVE>/codes/.

Examples:
    python tools/extract.py                   # every CVE
    python tools/extract.py --cwe 79 --cwe 89 # CVEs labeled CWE-79 or CWE-89
    python tools/extract.py CVE-2010-10010    # one CVE

Each archive is checked against the sha256 values in its meta.json. A CVE whose
codes/ directory already exists is skipped unless --force is given.
Requires Python 3.12 or later and no third-party packages.
"""
import argparse
import hashlib
import json
import shutil
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class Parts:
    """Read the archive parts as one stream and hash the bytes read."""

    def __init__(self, cve_dir, parts):
        self.files = [(cve_dir / p["path"], p["sha256"]) for p in parts]
        self.total = hashlib.sha256()
        self.part = None
        self.fh = None
        self.expected = None

    def _next(self):
        if self.fh:
            self._close_part()
        if not self.files:
            return False
        path, self.expected = self.files.pop(0)
        self.fh = open(path, "rb")
        self.part = hashlib.sha256()
        return True

    def _close_part(self):
        self.fh.close()
        self.fh = None
        if self.part.hexdigest() != self.expected:
            raise ValueError("sha256 mismatch in an archive part")

    def read(self, n=-1):
        if self.fh is None and not self._next():
            return b""
        while True:
            b = self.fh.read(n)
            if b:
                self.part.update(b)
                self.total.update(b)
                return b
            if not self._next():
                return b""

    def drain(self):
        while self.read(1 << 20):
            pass


def extract(cve_dir, force):
    meta = json.loads((cve_dir / "meta.json").read_text())
    pkg = meta["source_package"]
    dest = cve_dir / "codes"
    if dest.exists() and not force:
        return "skipped"
    tmp = cve_dir / "codes.partial"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    stream = Parts(cve_dir, pkg["parts"])
    try:
        with tarfile.open(fileobj=stream, mode="r|xz") as tar:
            tar.extractall(tmp, filter="tar")
        stream.drain()
        if stream.total.hexdigest() != pkg["archive_sha256"]:
            raise ValueError("archive sha256 mismatch")
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    shutil.rmtree(dest, ignore_errors=True)
    tmp.rename(dest)
    return "extracted"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cves", nargs="*", help="CVE ids to extract (default: all)")
    ap.add_argument("--cwe", action="append", default=[], help="CWE number, e.g. 79; repeatable")
    ap.add_argument("--force", action="store_true", help="re-extract CVEs whose codes/ exists")
    args = ap.parse_args()

    wanted_cwes = {f"CWE-{c.upper().removeprefix('CWE-')}" for c in args.cwe}
    dirs = sorted(p.parent for p in (ROOT / "cves").glob("*/meta.json"))
    if args.cves:
        names = set(args.cves)
        missing = names - {d.name for d in dirs}
        if missing:
            sys.exit(f"unknown CVE: {', '.join(sorted(missing))}")
        dirs = [d for d in dirs if d.name in names]
    if wanted_cwes:
        dirs = [d for d in dirs
                if wanted_cwes & set(json.loads((d / "meta.json").read_text())["cwe_ids"])]

    failed = 0
    for i, d in enumerate(dirs, 1):
        try:
            status = extract(d, args.force)
        except Exception as e:
            status, failed = f"FAILED: {e}", failed + 1
        print(f"[{i}/{len(dirs)}] {d.name} {status}", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
