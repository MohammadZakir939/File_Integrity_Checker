# File Integrity Checker

A command-line security tool that detects unauthorized changes to log files using **SHA-256 cryptographic hashing**.

---

## What it does

Every file has a unique "fingerprint" called a hash. This tool:

1. **Stores** the fingerprint of your log files (baseline)
2. **Compares** future fingerprints against the baseline
3. **Alerts** you if any file was modified — even a single character change is caught

This is the same technique used in real-world security systems (file integrity monitoring / FIM).

---

## How to run

> Requires Python 3.6 or higher. No extra libraries needed.

### Commands

```bash
# Store hashes of all files in a folder (run this first)
python integrity_checker.py init /path/to/logs

# Check a single file
python integrity_checker.py check /path/to/logs/app.log

# Check an entire folder
python integrity_checker.py check /path/to/logs

# Update the stored hash after an intentional change
python integrity_checker.py update /path/to/logs/app.log

# List all tracked files
python integrity_checker.py list
```

### Example output

```
─────────────────────────────────────────────────────
  Integrity Check Report  —  2024-01-15 10:32:44
─────────────────────────────────────────────────────
  ✅  auth.log
       Status : Unmodified

  ⚠️   syslog
       Status : MODIFIED — possible tampering detected!
       Stored hash  : 2cf24dba5fb0a30e26e83b2ac5b9...
       Current hash : 9f86d081884c7d659a2feaa0c55...
─────────────────────────────────────────────────────
  Summary: 1 unmodified  |  1 modified  |  0 new
─────────────────────────────────────────────────────
```

---

## How it works

```
Your log file  ──►  SHA-256 algorithm  ──►  64-character hash (fingerprint)
                                                    │
                                              stored in hashes.json
                                                    │
Later, run check ──► new hash computed ──► compared ──► Match? Safe. No match? Tampered!
```

SHA-256 is a one-way function — you cannot reverse the hash back to the file. Even changing one space in a file produces a completely different hash.

---

## Files in this project

| File | Purpose |
|------|---------|
| `integrity_checker.py` | Main tool — all commands live here |
| `file_integrity_checker.ipynb` | Google Colab notebook with explanations |
| `sample_logs/` | Sample log files to test with |
| `hashes.json` | Auto-created when you run `init` (gitignored) |

---

## Try it yourself (quick demo)

```python
# In Google Colab or any Python environment:

# 1. Create a test log
with open("test.log", "w") as f:
    f.write("User logged in at 10:00\n")

# 2. Store its hash
from integrity_checker import init, check
init("test.log")    # stores fingerprint

# 3. Tamper with it
with open("test.log", "w") as f:
    f.write("HACKED\n")

# 4. Detect the change
check("test.log")   # prints: MODIFIED ⚠️
```

---

## What I learned building this

- How **SHA-256 hashing** works and why it's used in security
- How to read and write files in Python using `open()`
- How to store structured data using **JSON**
- How to build a **command-line tool** with multiple sub-commands
- How file integrity monitoring (FIM) works in real security products

---

## Technologies used

- Python 3 (standard library only — `hashlib`, `os`, `json`, `sys`)
- SHA-256 cryptographic hash function
- JSON for persistent storage

---

## Author

Built as a cybersecurity learning project.
