#!/usr/bin/env python3
"""
File Integrity Checker
----------------------
Detects tampering in log files using SHA-256 cryptographic hashing.

Usage:
    python integrity_checker.py init <path>       # store hashes
    python integrity_checker.py check <path>      # compare hashes
    python integrity_checker.py update <path>     # update a hash
    python integrity_checker.py list              # show all tracked files
"""

import hashlib
import os
import json
import sys
from datetime import datetime


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

HASH_DB = "hashes.json"   # file where all hashes are stored


# ──────────────────────────────────────────────
# Core: compute SHA-256 hash of a file
# ──────────────────────────────────────────────

def compute_hash(filepath):
    """
    Read a file in chunks and return its SHA-256 fingerprint.
    Reading in chunks (4096 bytes) handles large files safely.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ──────────────────────────────────────────────
# Load / save the hash database (hashes.json)
# ──────────────────────────────────────────────

def load_db():
    """Load existing hash database, or return empty dict if none exists."""
    if not os.path.exists(HASH_DB):
        return {}
    with open(HASH_DB, "r") as f:
        return json.load(f)


def save_db(data):
    """Save the hash database to hashes.json."""
    with open(HASH_DB, "w") as f:
        json.dump(data, f, indent=2)


# ──────────────────────────────────────────────
# Helper: collect all file paths from input
# ──────────────────────────────────────────────

def collect_files(path):
    """
    Return a list of file paths.
    - If path is a single file, return [path].
    - If path is a directory, walk it and return all files inside.
    """
    if os.path.isfile(path):
        return [path]
    elif os.path.isdir(path):
        all_files = []
        for root, dirs, files in os.walk(path):
            for filename in files:
                all_files.append(os.path.join(root, filename))
        return all_files
    else:
        print(f"[ERROR] Path not found: {path}")
        return []


# ──────────────────────────────────────────────
# Command: init
# ──────────────────────────────────────────────

def init(path):
    """
    Scan a file or folder and store hashes for all files.
    Records timestamp so you know when the baseline was created.
    """
    files = collect_files(path)
    if not files:
        return

    db = load_db()
    new_count = 0
    updated_count = 0

    for filepath in files:
        abs_path = os.path.abspath(filepath)
        file_hash = compute_hash(abs_path)
        is_new = abs_path not in db

        db[abs_path] = {
            "hash": file_hash,
            "last_updated": datetime.now().isoformat(),
            "size_bytes": os.path.getsize(abs_path)
        }

        if is_new:
            new_count += 1
        else:
            updated_count += 1

    save_db(db)
    print(f"\n✅ Hashes stored successfully.")
    print(f"   New files recorded : {new_count}")
    print(f"   Re-hashed files    : {updated_count}")
    print(f"   Database saved to  : {HASH_DB}\n")


# ──────────────────────────────────────────────
# Command: check
# ──────────────────────────────────────────────

def check(path):
    """
    Compare current file hashes against the stored baseline.
    Reports: Unmodified / Modified / New (not in database).
    """
    db = load_db()

    if not db:
        print("\n[ERROR] No hash database found. Run 'init' first.\n")
        return

    files = collect_files(path)
    if not files:
        return

    print(f"\n{'─'*55}")
    print(f"  Integrity Check Report  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*55}")

    unmodified = 0
    modified = 0
    new_files = 0

    for filepath in files:
        abs_path = os.path.abspath(filepath)
        display = os.path.basename(abs_path)

        if abs_path not in db:
            print(f"  🆕  {display}")
            print(f"       Status : NEW FILE (not in database)")
            new_files += 1
        else:
            current_hash = compute_hash(abs_path)
            stored_hash  = db[abs_path]["hash"]

            if current_hash == stored_hash:
                print(f"  ✅  {display}")
                print(f"       Status : Unmodified")
                unmodified += 1
            else:
                print(f"  ⚠️   {display}")
                print(f"       Status : MODIFIED — possible tampering detected!")
                print(f"       Stored hash  : {stored_hash[:32]}...")
                print(f"       Current hash : {current_hash[:32]}...")
                modified += 1

    print(f"{'─'*55}")
    print(f"  Summary: {unmodified} unmodified  |  {modified} modified  |  {new_files} new")
    print(f"{'─'*55}\n")


# ──────────────────────────────────────────────
# Command: update
# ──────────────────────────────────────────────

def update(path):
    """
    Update the stored hash for a specific file.
    Use this after you've intentionally changed a file and want
    to accept its new state as the new baseline.
    """
    db = load_db()

    if not db:
        print("\n[ERROR] No hash database found. Run 'init' first.\n")
        return

    if not os.path.isfile(path):
        print(f"\n[ERROR] Not a file: {path}\n")
        return

    abs_path = os.path.abspath(path)
    new_hash = compute_hash(abs_path)

    db[abs_path] = {
        "hash": new_hash,
        "last_updated": datetime.now().isoformat(),
        "size_bytes": os.path.getsize(abs_path)
    }

    save_db(db)
    print(f"\n✅ Hash updated successfully for: {abs_path}")
    print(f"   New hash : {new_hash}\n")


# ──────────────────────────────────────────────
# Command: list
# ──────────────────────────────────────────────

def list_files():
    """Show all files currently tracked in the hash database."""
    db = load_db()

    if not db:
        print("\n[INFO] No hash database found. Run 'init' first.\n")
        return

    print(f"\n{'─'*55}")
    print(f"  Tracked Files ({len(db)} total)")
    print(f"{'─'*55}")

    for filepath, data in db.items():
        print(f"  📄 {os.path.basename(filepath)}")
        print(f"     Path    : {filepath}")
        print(f"     Hash    : {data['hash'][:32]}...")
        print(f"     Updated : {data['last_updated']}")
        print(f"     Size    : {data['size_bytes']} bytes")
        print()

    print(f"{'─'*55}\n")


# ──────────────────────────────────────────────
# Main: parse command and run
# ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1].lower()

    if command == "init":
        if len(sys.argv) < 3:
            print("[ERROR] Provide a path.  Example: python integrity_checker.py init /var/log")
            return
        init(sys.argv[2])

    elif command == "check":
        if len(sys.argv) < 3:
            print("[ERROR] Provide a path.  Example: python integrity_checker.py check /var/log")
            return
        check(sys.argv[2])

    elif command == "update":
        if len(sys.argv) < 3:
            print("[ERROR] Provide a file path.  Example: python integrity_checker.py update /var/log/syslog")
            return
        update(sys.argv[2])

    elif command == "list":
        list_files()

    else:
        print(f"[ERROR] Unknown command: '{command}'")
        print("Valid commands: init, check, update, list")


if __name__ == "__main__":
    main()
