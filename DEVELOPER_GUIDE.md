# MallnSight — Developer Guide

Technical documentation for setting up, understanding, and extending the
MallnSight codebase.

---

## 1. Project Structure

```
mallnsight/
├── app.py                  # Flask routes & request handling
├── analysis/
│   ├── hash.py               # MD5 / SHA1 / SHA256
│   ├── metadata.py            # File info (size, MIME, extension)
│   ├── pe_analysis.py          # PE header / sections / imports / exports
│   ├── entropy.py              # Shannon entropy
│   ├── strings.py               # String extraction + suspicious indicators
│   ├── yara_scan.py              # YARA rule compilation & scanning
│   ├── scoring.py                 # Risk score & verdict
│   ├── report.py                   # PDF report generation
│   └── history.py                    # MongoDB Atlas cloud history (optional)
├── yara_rules/                       # Bundled .yar rule files
├── templates/                          # Jinja2 pages
├── static/                               # CSS / JS / assets
├── tests/                                  # pytest smoke tests
├── uploads/                                  # Uploaded files (runtime only, gitignored)
├── reports/                                    # Generated PDF reports (runtime only, gitignored)
├── requirements.txt                              # Production dependencies
├── requirements-dev.txt                            # + pytest, for development/CI
├── Procfile                                          # Render/production start command
├── runtime.txt                                         # Pinned Python version for deployment
├── .env.example                                          # Template for MONGODB_URI etc. (copy to .env)
└── .github/workflows/ci.yml                              # GitHub Actions CI
```

---

## 2. Local Setup

### Prerequisites

- Python 3.11 or 3.12 (these have prebuilt `yara-python` wheels)
- On Windows, building `yara-python` from source requires the
  [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

### Install

```bash
git clone git@github.com:vibushasatheeshkumar/mallnsight.git
cd mallnsight

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

pip install -r requirements-dev.txt   # includes pytest for development
```

### Run

```bash
python app.py
```

Starts at `http://127.0.0.1:5000`. Debug mode is off by default; enable
it with:

```bash
# Windows PowerShell
$env:FLASK_DEBUG="1"; python app.py

# macOS/Linux
FLASK_DEBUG=1 python app.py
```

> Debug mode also enables Jinja's template auto-reload — without it,
> the dev server caches compiled templates in memory and won't pick up
> template edits until restarted.

---

## 3. Architecture Overview

MallnSight is a single Flask process with no background workers. It has
no *required* database — file analysis itself is entirely local. The
only optional network dependency is MongoDB Atlas, used solely to save
a small analysis summary for the `/history` page; if it's not
configured, the app behaves exactly as if it didn't exist. Each request
to `/analyze`:

1. Validates and stores the upload (`app.py`).
2. Calls each analysis module in `analysis/` in sequence, passing the
   stored file path.
3. Passes all module outputs to `calculate_score()`.
4. Passes everything to `generate_report()` to build a PDF.
5. Saves a summary to MongoDB Atlas via `save_analysis()` (no-op if not configured).
6. Renders `dashboard.html` with all the collected data.

Every module in `analysis/` follows the same contract: **take a file
path in, return a plain `dict` out.** No module shares state with
another, and none of them write to global/module-level mutable state
except `yara_scan.py`, which caches the *compiled ruleset* (not
per-request data) so rules aren't recompiled on every request.

---

## 4. Module Reference

### `analysis/hash.py`

```python
calculate_hashes(file_path) -> {"md5": str, "sha1": str, "sha256": str}
```

Reads the file in 4 KB chunks to avoid loading large files fully into
memory.

### `analysis/metadata.py`

```python
get_metadata(file_path) -> {"name": str, "size": float (KB), "extension": str, "mime": str|None}
```

### `analysis/pe_analysis.py`

```python
analyze_pe(file_path) -> {
    "architecture": str, "compile_time": str, "entry_point": str,
    "image_base": str, "number_of_sections": int,
    "sections": [{"name", "virtual_size", "raw_size", "entropy"}],
    "imports": [{"dll", "function"}], "exports": [str]
} | {"error": str}   # if not a valid PE file
```

Uses `pefile`. Always check `pe_info.get("error")` before reading other
keys.

### `analysis/entropy.py`

```python
calculate_entropy(data: bytes) -> float          # raw Shannon entropy helper
analyze_entropy(file_path) -> {"entropy": float, "max_entropy": 8.0, "verdict": str}
```

### `analysis/strings.py`

```python
extract_strings(file_path, min_length=4, max_strings=500) -> {
    "total_strings": int,
    "strings": [str, ...],          # capped at max_strings
    "suspicious": [{"category": str, "value": str}]
}
```

To add a new suspicious-indicator category, add an entry to the
`SUSPICIOUS_PATTERNS` dict (category name → compiled regex).

### `analysis/yara_scan.py`

```python
scan_file(file_path) -> {
    "available": bool,    # False if yara-python isn't installed, or rules failed to compile
    "error": str|None,
    "matches": [{"rule": str, "description": str, "severity": "HIGH"|"MEDIUM"|"LOW"}]
}
```

Compiles every `*.yar` file found in `yara_rules/` once, then caches the
compiled `yara.Rules` object at module level for subsequent requests.

### `analysis/scoring.py`

```python
calculate_score(entropy_info, yara_info, strings_info, pe_info) -> {
    "score": int (0-100), "verdict": str, "reasons": [str, ...]
}
```

Scoring weights (see `SEVERITY_WEIGHTS` and `calculate_score` body):

| Signal | Points |
|---|---|
| Entropy ≥ 7.5 | +30 |
| Entropy ≥ 6.5 | +15 |
| YARA match, severity HIGH | +25 each |
| YARA match, severity MEDIUM | +15 each |
| YARA match, severity LOW | +5 each |
| Each distinct suspicious-string category | +8 |
| Any PE section with entropy ≥ 7.5 | +10 (once) |

Score is capped at 100. Verdict thresholds: `≥70` HIGH RISK, `≥40`
SUSPICIOUS, `≥15` LOW RISK, else CLEAN.

### `analysis/report.py`

```python
generate_report(metadata, hashes, pe_info, entropy_info, strings_info, yara_info, score_info) -> str (file path)
```

Builds a PDF with `reportlab.platypus` and saves it to `reports/`,
named `<basename>_<UTC timestamp>.pdf`.

### `analysis/history.py` (cloud feature — MongoDB Atlas)

```python
is_available() -> bool                     # True if MONGODB_URI is set and reachable
get_connection_error() -> str | None        # human-readable reason if not available
save_analysis(metadata, hashes, score_info) -> str | None   # inserted record id, or None
get_recent_analyses(limit=50) -> list[dict]                  # newest first, [] if unavailable
```

Connects lazily — nothing is attempted until the first request that
needs it, and the connection (or failure) is cached for the life of the
process. Every call is wrapped so a missing/unreachable database never
raises into the request handler; it just degrades to "unavailable."

**Setup:** copy `.env.example` to `.env` and set `MONGODB_URI` to your
MongoDB Atlas connection string (see `README.md` → "Cloud History
Setup" for the step-by-step Atlas walkthrough). The app loads `.env` via
`python-dotenv` at startup (`app.py`, before any other imports).

Each saved record is a small summary document, **not** the file itself:

```json
{
  "filename": "sample.exe",
  "size_kb": 7421.5,
  "md5": "...", "sha1": "...", "sha256": "...",
  "risk_score": 63,
  "verdict": "SUSPICIOUS",
  "reasons": ["YARA rule matched: Suspicious_AntiDebug_AntiVM"],
  "analyzed_at": "2026-06-29T10:15:00Z"
}
```

---

## 5. Adding a New YARA Rule

1. Create or edit a `.yar` file inside `yara_rules/`.
2. Every rule **must** set a `severity` meta field to `"HIGH"`,
   `"MEDIUM"`, or `"LOW"` — this feeds directly into the risk score.

```yara
rule My_New_Rule
{
    meta:
        description = "Explain what this rule detects"
        severity = "MEDIUM"

    strings:
        $a = "some_suspicious_string"

    condition:
        $a
}
```

3. No code changes or restarts are needed in debug mode — rules are
   recompiled the first time `scan_file()` runs after a server restart
   (the compiled ruleset is cached for the process lifetime, so restart
   the app to pick up new/edited rule files).

---

## 6. Adding a New Analysis Module

1. Create `analysis/your_module.py` with a single function:
   `your_function(file_path) -> dict`.
2. Import and call it in `app.py`'s `/analyze` route, alongside the
   existing calls.
3. Pass its output into `calculate_score()` if it should affect the risk
   score, and into `generate_report()` if it should appear in the PDF.
4. Add the corresponding fields to `templates/dashboard.html`.
5. Add a test case to `tests/test_app.py`.

---

## 7. Testing

```bash
pytest tests/ -v
```

`tests/test_app.py` uses Flask's test client (no real server needed):

- Every static page route returns 200.
- `/analyze` returns 400 for a missing file and for a disallowed
  extension, 405 for GET.
- A real PE file (the active Python interpreter's `python.exe`) is
  uploaded and the response is asserted to contain `Risk Score`.

CI (`.github/workflows/ci.yml`) runs this suite automatically on
Python 3.11 and 3.12 for every push/PR to `main`.

---

## 8. Deployment

- `Procfile`: `web: waitress-serve --host=0.0.0.0 --port=$PORT app:app`
- `runtime.txt`: pins the Python version for the host platform.
- On Render: **New → Web Service** → connect the GitHub repo → Build
  Command `pip install -r requirements.txt` → Start Command is read
  automatically from the `Procfile`.
- The hosting filesystem is ephemeral — don't rely on `uploads/` or
  `reports/` persisting across deploys/restarts unless you add external
  storage.

---

## 9. Coding Conventions Used in This Repo

- Each `analysis/*.py` module is a **pure function over a file path** —
  no shared mutable state, no side effects beyond reading the file (and,
  for `yara_scan.py`, an in-memory compiled-rules cache).
- Flask routes in `app.py` validate input early and return explicit
  HTTP status codes (400/404/405) rather than letting exceptions bubble
  up.
- Debug mode is opt-in via `FLASK_DEBUG=1`, never hardcoded on.
- Uploaded files are always renamed to a UUID-based filename before
  being written to disk — the original filename is only used for
  display, never for file paths.

---

## 10. Known Gotchas

- **Jinja template caching**: with `debug=False`, Flask does not
  auto-reload templates. If you edit a `.html` file while the dev server
  is running without `FLASK_DEBUG=1`, restart the process to see the
  change.
- **`yara-python` build failures on Windows**: if `pip install` fails
  with "Microsoft Visual C++ 14.0 or greater is required" even after
  installing the Build Tools, run the install from inside a
  `vcvars64.bat`-initialized shell with `DISTUTILS_USE_SDK=1` and
  `MSSdk=1` set.
- **Multiple stale dev server processes**: if you've started/stopped
  `python app.py` several times in the same terminal session, check for
  leftover processes still bound to port 5000 before assuming a code
  change isn't taking effect.
- **MongoDB Atlas connection hangs/fails**: usually the cluster's
  Network Access list doesn't include your current IP (or `0.0.0.0/0`
  for quick testing). `analysis/history.py` connects with a 5-second
  timeout, so a misconfigured allowlist shows up as `/history` reporting
  "unavailable" rather than the app hanging.
- **`/history` works locally but says "unavailable" on Render**: `.env`
  is gitignored and never deployed — it only configures your local
  machine. `MONGODB_URI` must be added separately as an environment
  variable in the Render dashboard (**Environment** tab on your
  service), and Atlas's Network Access must allow `0.0.0.0/0` since
  Render's free tier has no fixed outbound IP. See `README.md` →
  "Enabling `/history` on Render."
- **`bad auth : authentication failed` from Atlas on Render, even after
  setting `MONGODB_URI` correctly on the service**: check Render's
  Environment tab for a **Linked Environment Group**. If the service
  also pulls `MONGODB_URI`/`MONGODB_DB` from a shared group, a stale
  value sitting in that group can conflict with (or take effect over)
  the one set directly on the service. Update the value in *both*
  places — the direct service variable and the linked group — to avoid
  ambiguity. Also watch for accidentally creating multiple Render
  services for the same repo while troubleshooting (e.g.
  `mallnsight`, `mallnsight-1`, `mallnsight-2`) — each has its own
  independent environment variables, so fixing one doesn't fix the
  others.
- **`history.py`'s connection is cached per-process**: once
  `_get_collection()` has run once (success or failure), it won't retry
  until the process restarts. Use `analysis.history._reset_cache()`
  (test-only) if you need to force a reconnect attempt within the same
  process, e.g. in tests.
