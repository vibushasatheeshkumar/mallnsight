# MallnSight — Project Documentation

**Static Malware Analysis & Threat Intelligence Platform**
Repository: https://github.com/vibushasatheeshkumar/mallnsight

---

## 1. Objectives / Aim

To build a web-based tool that lets a user upload a suspicious file and
get an automated **static** (non-executing) security analysis of it —
combining file hashing, executable structure inspection, entropy
analysis, suspicious string detection, and YARA signature scanning into
one risk score and a downloadable report.

**Specific objectives:**

- Allow file upload through a simple web interface.
- Generate MD5/SHA1/SHA256 hashes for the file.
- Analyze PE (Windows executable) structure where applicable.
- Detect packed/encrypted content using entropy analysis.
- Extract and flag suspicious strings (APIs, commands, IPs, URLs).
- Scan the file against YARA rules for known malicious patterns.
- Combine all signals into a single risk score and verdict.
- Let the user download a PDF investigation report.
- Persist a summary of each analysis to a cloud database, so results
  remain browsable after the local session ends.
- Never execute the uploaded file at any point.

---

## 2. Introduction

Malware analysis is generally split into two approaches: **dynamic
analysis** (running the file in a sandbox and observing its behavior)
and **static analysis** (inspecting the file's content and structure
without running it). Static analysis is safer, faster, and is normally
the first step taken before a file is escalated to a full sandbox.

In practice, static analysis is usually done with several separate
command-line tools — one for hashing, one for parsing PE headers, one for
extracting strings, one for YARA scanning — and the analyst manually
combines the results. **MallnSight** automates this entire workflow
behind a single "Upload File" button and presents the combined result on
one dashboard, with an exportable PDF report and a cloud-backed history
of past analyses.

---

## 3. Problem Statement

There is no simple, free, offline tool that:

1. Takes a single file as input,
2. Runs multiple static-analysis techniques on it automatically,
3. Combines the results into one understandable risk score, and
4. Produces a shareable report —

without requiring the analyst to install and run several separate
command-line tools, manually interpret each tool's raw output, or take
the risk of accidentally executing the file.

---

## 4. Proposed Solution

MallnSight solves this by providing:

- A single upload form that triggers a complete analysis pipeline.
- Independent analysis modules for hashing, metadata, PE structure,
  entropy, strings, and YARA — each one only *reads* the file, never
  executes it.
- A scoring engine that converts all the individual results into one
  0–100 risk score and a plain-English verdict.
- A web dashboard showing every result clearly, plus a one-click PDF
  export of the same information.
- A cloud database (MongoDB Atlas) that saves a summary of each
  analysis so it remains visible on a History page later.
- An extensible YARA rule folder, so new detection rules can be added
  without changing any code.

---

## 5. System Architecture

MallnSight is a **monolithic, server-rendered web application** — a
single Flask process handles both the HTTP layer and the analysis
pipeline. No database is *required* to run the core analysis feature;
one cloud database (MongoDB Atlas) is used, optionally, purely to
persist analysis summaries for the History page.

**Components:**

| Component | Responsibility |
|---|---|
| **Browser (client)** | Bootstrap 5 + vanilla JS, renders server-sent Jinja2 HTML |
| **Flask application (`app.py`)** | Routing, upload validation (extension allow-list, 100 MB cap, UUID storage names), orchestrates the analysis pipeline |
| **Analysis engine (`analysis/`)** | Independent modules: hashing, metadata, PE parsing, entropy, strings, YARA, scoring, PDF report |
| **Local storage (`uploads/`, `reports/`)** | Holds the uploaded file and generated PDF for the duration of one request; ephemeral, gitignored |
| **Cloud database (MongoDB Atlas)** | Stores a small per-analysis summary (hashes, score, verdict, timestamp) for the `/history` page; optional, configured via `MONGODB_URI` |

See Section 6 for the full architecture diagram.

---

## 6. Diagrams

### 6.1 System Architecture Diagram

```
                        ┌──────────────────────────┐
                        │         Browser           │
                        │  (Bootstrap 5 + vanilla   │
                        │   JS, server-rendered      │
                        │   Jinja2 templates)         │
                        └────────────┬───────────────┘
                                     │ HTTP (multipart/form-data)
                                     ▼
                        ┌──────────────────────────┐
                        │     Flask Application      │
                        │         (app.py)            │
                        │  - Route handling            │
                        │  - Upload validation          │
                        └────────────┬─────────────────┘
                                     │ delegates to
                                     ▼
              ┌──────────────────────────────────────────────┐
              │                Analysis Engine                  │
              │                (analysis/ package)                │
              │  hash.py · metadata.py · pe_analysis.py            │
              │  entropy.py · strings.py · yara_scan.py             │
              │  scoring.py · report.py · history.py                 │
              └───────────────────────┬──────────────────────────────┘
                                      │ writes
                ┌─────────────────────┼─────────────────────────┐
                ▼                     ▼                         ▼
        uploads/<uuid>.ext    reports/<name>_<ts>.pdf    MongoDB Atlas
       (ephemeral, gitignored) (ephemeral, gitignored)  "analyses" collection
                                                          (cloud, persistent,
                                                           optional)
```

### 6.2 High-Level User Flow

```
 ┌──────────┐     ┌───────────┐     ┌───────────────┐     ┌────────────┐
 │  Upload  │ ──▶ │ Validate  │ ──▶ │   Run Static   │ ──▶ │  Show on   │
 │   File   │     │  (type &  │     │    Analysis     │     │ Dashboard  │
 │          │     │   size)   │     │    Pipeline       │     │            │
 └──────────┘     └───────────┘     └───────────────┘     └─────┬──────┘
                                                                    │
                                          ┌─────────────────────────┴────────────┐
                                          ▼                                      ▼
                               ┌──────────────────┐                  ┌───────────────────┐
                               │ Download PDF      │                  │ Saved to Cloud      │
                               │ Report (optional) │                  │ History (optional)   │
                               └──────────────────┘                  └───────────────────┘
```

### 6.3 Analysis Pipeline (Detailed)

```
                     uploaded file
                          │
        ┌─────────────────┼─────────────────────────────┐
        ▼                 ▼                              ▼
   calculate_hashes()  get_metadata()              analyze_pe()
   (MD5/SHA1/SHA256)   (size/MIME/ext)        (headers/sections/imports)
        │                 │                              │
        └─────────────────┴─────────────┬────────────────┘
                                         ▼
                               analyze_entropy()
                              (whole-file entropy)
                                         │
                                         ▼
                               extract_strings()
                         (strings + suspicious indicators)
                                         │
                                         ▼
                                 scan_file()
                               (YARA rule matches)
                                         │
                                         ▼
                              calculate_score()
                       (combines everything → risk score)
                                         │
                  ┌──────────────────────┼───────────────────────┐
                  ▼                      ▼                       ▼
         render dashboard.html   generate_report()      save_analysis()
        (shown to the user)    (PDF saved to reports/)  (MongoDB Atlas,
                                                          optional)
```

### 6.4 Request/Response Sequence

```
Browser            Flask App (app.py)         Analysis Modules
  │  POST /analyze        │                          │
  │ ─────────────────────▶│                          │
  │                       │── validate file ────────▶│
  │                       │── run pipeline ──────────▶│
  │                       │◀── results dict ──────────│
  │                       │── generate PDF ──────────▶│
  │                       │◀── pdf file path ─────────│
  │                       │── save_analysis() ───────▶│ (MongoDB Atlas)
  │◀── dashboard.html ────│                          │
  │  GET /download/<id>   │                          │
  │ ─────────────────────▶│                          │
  │◀── PDF file ──────────│                          │
  │  GET /history         │                          │
  │ ─────────────────────▶│── get_recent_analyses() ─▶│ (MongoDB Atlas)
  │◀── history.html ──────│                          │
```

---

## 7. Database Design

MallnSight's core analysis pipeline needs no database — a file is
uploaded, analyzed, rendered into a dashboard, and optionally exported
to PDF, all within one HTTP request-response pair.

A **cloud database (MongoDB Atlas)** is used for exactly one purpose:
persisting a summary of each analysis for the `/history` page, since a
purely request-scoped design can't offer that on its own. It's
implemented as a single document-store collection (no relational
schema/joins needed, since each record is flat and self-contained):

**Collection: `analyses`** (database `mallnsight`)

| Field | Type | Description |
|---|---|---|
| `_id` | ObjectId | MongoDB-generated primary key |
| `filename` | string | Original uploaded filename |
| `size_kb` | number | File size in KB |
| `md5`, `sha1`, `sha256` | string | File hashes |
| `risk_score` | int | 0–100 |
| `verdict` | string | `CLEAN` / `LOW RISK` / `SUSPICIOUS` / `HIGH RISK` |
| `reasons` | array of strings | Human-readable scoring reasons |
| `analyzed_at` | datetime (UTC) | When the analysis was run |

Implemented in `analysis/history.py` via `pymongo`. The connection is
lazy (made on first use, not at startup) and the result — success or
failure — is cached for the process lifetime. The feature is entirely
optional, controlled by the `MONGODB_URI` environment variable; the
rest of the application behaves identically whether it's configured or
not.

---

## 8. Workflow

End-to-end flow for a single analysis:

1. **Upload** — user submits a file via `/upload` to the `/analyze`
   endpoint (`multipart/form-data`, POST only).
2. **Validation** — filename is sanitized, extension checked against an
   allow-list, request size capped at 100 MB.
3. **Storage** — file is saved under `uploads/<uuid4>.<ext>`.
4. **Analysis pipeline** — hashing → metadata → PE analysis → entropy →
   string extraction → YARA scan, each module independent and read-only.
5. **Scoring** — all signals combined into one 0–100 score and verdict.
6. **Reporting** — full results rendered into a PDF, saved to `reports/`.
7. **Cloud save** — a summary (hashes, score, verdict, timestamp) is
   saved to MongoDB Atlas, if configured (silently skipped if not).
8. **Response** — `dashboard.html` rendered with every result.
9. **History (optional, later)** — `/history` reads recent summaries
   back from MongoDB Atlas and lists them, newest first.

---

## 9. Technical Implementation

| Layer | Technology | Detail |
|---|---|---|
| Web framework | Flask | Routes: `/`, `/about`, `/features`, `/upload`, `/contact`, `/history`, `POST /analyze`, `GET /download/<id>` |
| File validation | Werkzeug | `secure_filename`, extension allow-list, 100 MB size cap, UUID-based storage names |
| Hashing | `hashlib` (stdlib) | MD5, SHA1, SHA256 computed via chunked (4 KB) reads |
| Metadata | `os`, `mimetypes` (stdlib) | filename, size, extension, MIME type |
| PE Analysis | `pefile` | architecture, compile time, entry point, sections (with per-section entropy), imports, exports |
| Entropy | `math`, `collections.Counter` | Shannon entropy formula over the whole file |
| String extraction | `re` (stdlib) | ASCII + UTF-16LE strings, regex-matched against 9 suspicious categories |
| YARA scanning | `yara-python` | Compiles all `.yar` files in `yara_rules/`, returns rule/description/severity per match |
| Scoring | custom (`scoring.py`) | Weighted sum of entropy, YARA severity, suspicious strings, high-entropy sections → 0–100 score + verdict |
| PDF report | `reportlab` | `SimpleDocTemplate` + `Platypus` tables mirroring the dashboard |
| Cloud database | MongoDB Atlas (`pymongo`) | `/history` feature — saves a summary of every analysis to a cloud-hosted MongoDB cluster; degrades gracefully if not configured |
| Frontend | Jinja2, Bootstrap 5, vanilla JS | Dark enterprise theme, drag-and-drop upload, scroll-reveal animation, copy-to-clipboard |
| Testing | `pytest` | Smoke tests for every route + the full analysis pipeline + cloud-history graceful degradation |
| CI/CD | GitHub Actions | Runs the test suite on Python 3.11 and 3.12 on every push/PR |
| Hosting | Render + Waitress | `Procfile` runs `waitress-serve --host=0.0.0.0 --port=$PORT app:app` |

---

## 10. Screenshots

### Home Page
![Home Page](screenshots/screenshot_home.png)

---

### Features Page
![Features Page](screenshots/screenshot_features.png)

---

### Upload Page
![Upload Page](screenshots/screenshot_upload.png)

---

### Analysis Dashboard — Verdict, File Info & Hashes
![Dashboard Top](screenshots/screenshot_dashboard_top.png)

---

### Analysis Dashboard — YARA Matches, Entropy & Strings
![Dashboard Bottom](screenshots/screenshot_dashboard_bottom.png)

---

### Cloud History Page (MongoDB Atlas)
![History Page](screenshots/screenshot_history.png)

---

### How to re-embed screenshots

```markdown
![Dashboard Screenshot](screenshots/dashboard.png)
```

(Create a `screenshots/` folder in the repo and place your images there.)

---

## 11. Testing Results

Testing was done using `pytest` with Flask's built-in test client
(`tests/test_app.py`). Actual run on this build:

```
collected 11 items

tests/test_app.py::test_static_pages_load[/]                                  PASSED
tests/test_app.py::test_static_pages_load[/about]                             PASSED
tests/test_app.py::test_static_pages_load[/features]                         PASSED
tests/test_app.py::test_static_pages_load[/upload]                          PASSED
tests/test_app.py::test_static_pages_load[/contact]                        PASSED
tests/test_app.py::test_static_pages_load[/history]                       PASSED
tests/test_app.py::test_analyze_requires_a_file                          PASSED
tests/test_app.py::test_analyze_rejects_get                             PASSED
tests/test_app.py::test_analyze_rejects_disallowed_extension           PASSED
tests/test_app.py::test_history_degrades_gracefully_without_mongodb_uri PASSED
tests/test_app.py::test_analyze_accepts_pe_file                       PASSED

11 passed in 0.54s
```

### Test Case Summary

| # | Test Case | Input | Expected Result | Actual Result |
|---|---|---|---|---|
| 1 | Load Home page | `GET /` | HTTP 200 | ✅ 200 |
| 2 | Load Documentation page | `GET /about` | HTTP 200 | ✅ 200 |
| 3 | Load Features page | `GET /features` | HTTP 200 | ✅ 200 |
| 4 | Load Upload page | `GET /upload` | HTTP 200 | ✅ 200 |
| 5 | Load Contact page | `GET /contact` | HTTP 200 | ✅ 200 |
| 6 | Load History page | `GET /history` | HTTP 200 | ✅ 200 |
| 7 | Analyze with no file | `POST /analyze` (empty) | HTTP 400 | ✅ 400 |
| 8 | Analyze via GET | `GET /analyze` | HTTP 405 | ✅ 405 |
| 9 | Analyze disallowed file type | `POST /analyze` with `.txt` | HTTP 400 | ✅ 400 |
| 10 | History page without MongoDB configured | `GET /history`, no `MONGODB_URI` | HTTP 200, "unavailable" message shown, no crash | ✅ 200, graceful message |
| 11 | Analyze a real PE file | `POST /analyze` with `python.exe` | HTTP 200, contains risk score | ✅ 200, risk score present |

### Manual End-to-End Result (sample run, with MongoDB Atlas live)

Uploading `python.exe` (the Python interpreter binary, used purely as a
real-world PE sample) produced:

| Field | Result |
|---|---|
| HTTP Status | 200 |
| Verdict | SUSPICIOUS |
| Risk Score | 63 / 100 |
| Reason | YARA match on `Suspicious_AntiDebug_AntiVM` (the CPython runtime does check for an attached debugger) |
| Saved to MongoDB Atlas | ✅ Yes — confirmed via direct query, document matched the schema in Section 7 |
| Shown on `/history` | ✅ Yes — listed with correct filename, hash, score, and verdict |

This confirms the full pipeline — hashing, PE analysis, entropy, string
extraction, YARA scanning, scoring, dashboard rendering, and cloud
history — works correctly end-to-end on a real file.

---

## 12. Challenges / Limitations

**Challenges faced during development:**

1. **`yara-python` had no prebuilt wheel** for the Python version used
   in development on Windows, so it had to be compiled from source. Even
   after installing the Microsoft C++ Build Tools, the build still failed
   until `DISTUTILS_USE_SDK=1` and `MSSdk=1` were set — a non-obvious
   environment-variable workaround.
2. **`requirements.txt` was silently saved as UTF-16**, which made every
   line unreadable to `pip` even though it looked normal when opened in
   a text editor. It had to be rewritten as plain UTF-8.
3. **The CI pipeline failed on GitHub Actions** because
   `requirements.txt` included `python-magic-bin`, a Windows-only package
   that isn't even used anywhere in the code — it had no Linux build, so
   every Linux CI run failed at the install step.
4. **Dead/unused template code.** Some HTML files had content placed
   after the Jinja `{% endblock %}` tag, which is silently ignored by
   the template engine — meaning that code never actually appeared on
   the page despite looking present in the file.
5. **Stale server processes during local testing.** Multiple background
   copies of the Flask dev server stayed running on the same port across
   testing sessions, causing the browser/curl to sometimes hit an old,
   outdated version of the app.
6. **`.env` doesn't deploy itself.** After configuring MongoDB Atlas
   locally, `/history` worked on `localhost` but still showed
   "unavailable" on the live Render deployment — because `.env` is
   gitignored by design and never reaches the deployed environment.
   `MONGODB_URI` has to be added a second time, directly in Render's
   own Environment settings, for the cloud feature to work on the
   public URL.
7. **A "Linked Environment Group" silently held a stale credential.**
   Even after setting the correct `MONGODB_URI` directly on the Render
   service, `/history` kept failing with `bad auth: authentication
   failed`. The cause: the same service was also linked to a shared
   Render "Environment Group" of the same name, which still held an
   older, no-longer-valid connection string, and the stale one took
   effect. Fixed by updating the value in the linked group as well, not
   just on the service directly. This was made harder to diagnose
   because multiple Render services (`mallnsight`, `mallnsight-1`,
   `mallnsight-2`) had been created during earlier troubleshooting, each
   with independent environment variables.

**Current limitations:**

- A full result (PE breakdown, strings, YARA matches) isn't saved
  anywhere — only a summary (hashes, score, verdict) is stored in
  MongoDB Atlas for the History page; the full dashboard view itself
  isn't reconstructable later.
- PE-specific analysis (sections, imports, exports) is only available
  for Windows executable files; other formats get limited information.
- Free-tier hosting (Render) has an ephemeral filesystem and may "sleep"
  after inactivity, causing a slow first load.
- No user accounts — anyone with the URL can use the analyzer, and the
  History page shows everyone's past analyses (no per-user separation).

---

## 13. Future Enhancements

- Add deeper analysis for non-PE files (PDF, ZIP, APK, Office documents).
- Store the *full* analysis result (not just a summary) in MongoDB Atlas
  so a past dashboard view can be reopened, not just its score.
- Add user accounts/login for multi-user usage.
- Add an optional sandboxed dynamic analysis mode.
- Cross-check file hashes against an external threat-intel API
  (e.g. VirusTotal), as an opt-in feature.
- Use machine learning to suggest a malware family, not just a score.
- Package the app with Docker for easier, OS-independent deployment.

---

## 14. Conclusion

MallnSight successfully brings together several static malware-analysis
techniques — hashing, PE structure inspection, entropy analysis, string
extraction, and YARA signature matching — into one simple web
application, backed by a cloud database for persistent history. A user
can upload a file and, within seconds, get a clear risk score, a
detailed breakdown of why that score was given, a downloadable PDF
report, and a record on the History page they can revisit later — all
without the file ever being executed. The project demonstrates that a
lightweight Flask application, combined with a narrowly-scoped cloud
database integration, is enough to replace a fragmented set of
command-line malware-analysis tools for first-pass triage.

---

## 15. References

1. Flask Documentation — https://flask.palletsprojects.com/
2. `pefile` (PE parsing library) — https://github.com/erocarrera/pefile
3. YARA Documentation — https://yara.readthedocs.io/
4. `yara-python` — https://github.com/VirusTotal/yara-python
5. ReportLab User Guide — https://www.reportlab.com/docs/reportlab-userguide.pdf
6. OWASP File Upload Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
7. Shannon, C.E., "A Mathematical Theory of Communication," Bell System Technical Journal, 1948.
8. Microsoft PE/COFF Specification — https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
9. MongoDB Atlas Documentation — https://www.mongodb.com/docs/atlas/
10. `pymongo` Documentation — https://pymongo.readthedocs.io/
11. Render Documentation — https://render.com/docs
12. Waitress WSGI Server — https://docs.pylonsproject.org/projects/waitress/

---

*See [USER_GUIDE.md](USER_GUIDE.md) for client-side how-to instructions
and [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for developer-side setup
and contribution documentation.*
