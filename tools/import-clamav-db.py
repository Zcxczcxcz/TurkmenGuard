#!/usr/bin/env python3
"""
Import ClamAV hash signatures (main.cvd + daily.cvd) into TurkmenGuard SQLite DB.

Requires: pip install cvdupdate (for downloading CVDs)
Usage:
  python import-clamav-db.py
  python import-clamav-db.py --cvd-dir ../Data/clamav-download --output ../Data/hash-signatures.db
"""
from __future__ import annotations

import argparse
import io
import re
import sqlite3
import struct
import subprocess
import sys
import tarfile
import zlib
from pathlib import Path

CVD_HEADER = 512
MAX_NAME_LEN = 128


def unpack_cvd(cvd_path: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = cvd_path.read_bytes()
    if len(raw) <= CVD_HEADER:
        raise ValueError(f"Invalid CVD: {cvd_path}")

    try:
        payload = zlib.decompress(raw[CVD_HEADER:])
    except zlib.error:
        # Some CLD files may differ; try raw tar
        payload = raw[CVD_HEADER:]

    extracted: list[Path] = []
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = Path(member.name).name
            if not (name.endswith(".hdb") or name.endswith(".hsb")):
                continue
            target = out_dir / name
            with tar.extractfile(member) as src, open(target, "wb") as dst:
                dst.write(src.read())
            extracted.append(target)
    return extracted


def parse_hash_line(line: str) -> tuple[str, str, str, int] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split(":")
    if len(parts) < 3:
        return None

    hash_hex = parts[0].strip().lower()
    size_part = parts[1].strip()
    name = parts[2].strip()

    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", hash_hex):
        return None

    if size_part == "*":
        size = -1
    else:
        try:
            size = int(size_part)
        except ValueError:
            return None

    if len(hash_hex) == 32:
        algo = "md5"
    elif len(hash_hex) == 40:
        algo = "sha1"
    else:
        algo = "sha256"

    # Skip known-bad empty-file MD5 with bogus size (ClamAV FP reports)
    if hash_hex == "d41d8cd98f00b204e9800998ecf8427e" and size > 0:
        return None

    return algo, hash_hex, name[:MAX_NAME_LEN], size


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        CREATE TABLE IF NOT EXISTS signatures (
            hash TEXT NOT NULL,
            algo TEXT NOT NULL,
            name TEXT NOT NULL,
            file_size INTEGER NOT NULL DEFAULT -1,
            severity INTEGER NOT NULL DEFAULT 4,
            source TEXT NOT NULL DEFAULT 'clamav',
            PRIMARY KEY (hash, algo)
        );
        CREATE INDEX IF NOT EXISTS idx_sig_hash ON signatures(hash);
        CREATE INDEX IF NOT EXISTS idx_sig_algo ON signatures(algo);
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        """
    )


def import_files(db_path: Path, hash_files: list[Path], version: str) -> dict[str, int]:
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    create_schema(conn)

    stats = {"lines": 0, "inserted": 0, "skipped": 0}
    batch: list[tuple] = []

    for hf in hash_files:
        print(f"  Parsing {hf.name}...")
        with open(hf, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stats["lines"] += 1
                parsed = parse_hash_line(line)
                if not parsed:
                    stats["skipped"] += 1
                    continue
                algo, h, name, size = parsed
                severity = 4  # High
                if name.lower().startswith("test.") or "eicar" in name.lower():
                    severity = 0
                batch.append((h, algo, name, size, severity))
                if len(batch) >= 50000:
                    conn.executemany(
                        "INSERT OR IGNORE INTO signatures (hash, algo, name, file_size, severity, source) VALUES (?, ?, ?, ?, ?, 'clamav')",
                        batch,
                    )
                    stats["inserted"] += len(batch)
                    batch.clear()

    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO signatures (hash, algo, name, file_size, severity, source) VALUES (?, ?, ?, ?, ?, 'clamav')",
            batch,
        )
        stats["inserted"] += len(batch)

    cur = conn.execute("SELECT COUNT(*) FROM signatures")
    total = cur.fetchone()[0]
    cur = conn.execute("SELECT algo, COUNT(*) FROM signatures GROUP BY algo")
    by_algo = dict(cur.fetchall())

    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('version', ?)", (version,))
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('source', 'clamav')")
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('main_version', ?)", (version,))
    conn.commit()
    conn.execute("VACUUM")
    conn.commit()
    conn.close()

    stats["total"] = total
    stats["by_algo"] = by_algo
    return stats


def download_with_cvdupdate(cvd_dir: Path) -> None:
    cvdupdate = Path.home() / "AppData/Roaming/Python/Python314/Scripts/cvdupdate.exe"
    if not cvdupdate.exists():
        for p in Path.home().glob("**/cvdupdate.exe"):
            cvdupdate = p
            break
    if not cvdupdate.exists():
        print("cvdupdate not found. Run: pip install cvdupdate")
        sys.exit(1)

    cvd_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(cvdupdate), "config", "set", "-d", str(cvd_dir)], check=True)
    subprocess.run([str(cvdupdate), "update", "-V"], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build TurkmenGuard hash DB from ClamAV")
    parser.add_argument("--cvd-dir", type=Path, default=Path(__file__).parent.parent / "Data" / "clamav-download")
    parser.add_argument("--output", type=Path, default=Path(__file__).parent.parent / "Data" / "hash-signatures.db")
    parser.add_argument("--download", action="store_true", help="Download CVDs via cvdupdate first")
    args = parser.parse_args()

    if args.download:
        print("Downloading ClamAV databases via cvdupdate...")
        download_with_cvdupdate(args.cvd_dir)

    unpack_dir = args.cvd_dir / "unpacked"
    hash_files: list[Path] = []

    for cvd_name in ("main.cvd", "daily.cvd"):
        cvd_path = args.cvd_dir / cvd_name
        if not cvd_path.exists():
            print(f"Missing {cvd_path}")
            sys.exit(1)
        print(f"Unpacking {cvd_name} ({cvd_path.stat().st_size / 1024 / 1024:.1f} MB)...")
        hash_files.extend(unpack_cvd(cvd_path, unpack_dir / cvd_name.replace(".cvd", "")))

    if not hash_files:
        print("No .hdb/.hsb files found in CVD archives")
        sys.exit(1)

    version = "clamav-main63-daily28059"
    dns = args.cvd_dir / "dns.txt"
    if dns.exists():
        version = dns.read_text(encoding="utf-8", errors="ignore").strip() or version

    print(f"Building SQLite DB: {args.output}")
    stats = import_files(args.output, hash_files, version)

    size_mb = args.output.stat().st_size / 1024 / 1024
    print(f"\nDone!")
    print(f"  Total signatures: {stats['total']:,}")
    print(f"  By algorithm:     {stats.get('by_algo', {})}")
    print(f"  DB size:          {size_mb:.1f} MB")
    print(f"  Output:           {args.output}")


if __name__ == "__main__":
    main()
