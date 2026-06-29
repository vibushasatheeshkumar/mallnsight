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
one dashboard, with an exportable PDF report.

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
- An extensible YARA rule folder, so new detection rules can be added
  without changing any code.

---

## 5. Workflow Diagrams

### 5.1 High-Level User Flow

```
 ┌──────────┐     ┌───────────┐     ┌───────────────┐     ┌────────────┐
 │  Upload  │ ──▶ │ Validate  │ ──▶ │   Run Static   │ ──▶ │  Show on   │
 │   File   │     │  (type &  │     │    Analysis     │     │ Dashboard  │
 │          │     │   size)   │     │    Pipeline       │     │            │
 └──────────┘     └───────────┘     └───────────────┘     └─────┬──────┘
                                                                    │
                                                                    ▼
                                                          ┌──────────────────┐
                                                          │ Download PDF      │
                                                          │ Report (optional) │
                                                          └──────────────────┘
```

### 5.2 Analysis Pipeline (Detailed)

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
                  ┌──────────────────────┴───────────────────────┐
                  ▼                                              ▼
         render dashboard.html                          generate_report()
        (shown to the user)                          (PDF saved to reports/)
```

### 5.3 Request/Response Sequence

```
Browser            Flask App (app.py)         Analysis Modules
  │  POST /analyze        │                          │
  │ ─────────────────────▶│                          │
  │                       │── validate file ────────▶│
  │                       │── run pipeline ──────────▶│
  │                       │◀── results dict ──────────│
  │                       │── generate PDF ──────────▶│
  │                       │◀── pdf file path ─────────│
  │◀── dashboard.html ────│                          │
  │  GET /download/<id>   │                          │
  │ ─────────────────────▶│                          │
  │◀── PDF file ──────────│                          │
```

---

## 6. Technical Implementation

| Layer | Technology | Detail |
|---|---|---|
| Web framework | Flask | Routes: `/`, `/about`, `/features`, `/upload`, `/contact`, `POST /analyze`, `GET /download/<id>` |
| File validation | Werkzeug | `secure_filename`, extension allow-list, 100 MB size cap, UUID-based storage names |
| Hashing | `hashlib` (stdlib) | MD5, SHA1, SHA256 computed via chunked (4 KB) reads |
| Metadata | `os`, `mimetypes` (stdlib) | filename, size, extension, MIME type |
| PE Analysis | `pefile` | architecture, compile time, entry point, sections (with per-section entropy), imports, exports |
| Entropy | `math`, `collections.Counter` | Shannon entropy formula over the whole file |
| String extraction | `re` (stdlib) | ASCII + UTF-16LE strings, regex-matched against 9 suspicious categories |
| YARA scanning | `yara-python` | Compiles all `.yar` files in `yara_rules/`, returns rule/description/severity per match |
| Scoring | custom (`scoring.py`) | Weighted sum of entropy, YARA severity, suspicious strings, high-entropy sections → 0–100 score + verdict |
| PDF report | `reportlab` | `SimpleDocTemplate` + `Platypus` tables mirroring the dashboard |
| Cloud database | MongoDB Atlas (`pymongo`) | Optional `/history` feature — saves a summary (hashes, score, verdict, timestamp) of every analysis to a cloud-hosted MongoDB cluster; degrades gracefully if not configured |
| Frontend | Jinja2, Bootstrap 5, vanilla JS | Dark enterprise theme, drag-and-drop upload, scroll-reveal animation, copy-to-clipboard |
| Testing | `pytest` | Smoke tests for every route + the full analysis pipeline |
| CI/CD | GitHub Actions | Runs the test suite on Python 3.11 and 3.12 on every push/PR |
| Hosting | Render + Waitress | `Procfile` runs `waitress-serve --host=0.0.0.0 --port=$PORT app:app` |

---

## 7. Screenshots

> Automated screenshots could not be generated in this environment (no
> headless browser tooling was available). Run the app locally
> (`python app.py`, then open `http://127.0.0.1:5000`) and paste your own
> screenshots into the slots below before submitting.

| Page | Screenshot |
|---|---|
| Home Page | _[insert screenshot of `/`]_ |
| Features Page | _[insert screenshot of `/features`]_ |
| Documentation Page | _[insert screenshot of `/about`]_ |
| Upload Page | _[insert screenshot of `/upload`]_ |
| Analysis Dashboard (after uploading a file) | _[insert screenshot of `/analyze` result]_ |
| PDF Report | _[insert screenshot of the downloaded PDF]_ |

To embed an image in this Markdown file once captured:

```markdown
![Dashboard Screenshot](screenshots/dashboard.png)
```

(Create a `screenshots/` folder in the repo and place your images there.)

---

## 8. Testing Results

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

### Manual End-to-End Result (sample run)

Uploading `python.exe` (the Python interpreter binary, used purely as a
real-world PE sample) produced:

| Field | Result |
|---|---|
| HTTP Status | 200 |
| Verdict | SUSPICIOUS |
| Risk Score | 63 / 100 |
| Reason | YARA match on `Suspicious_AntiDebug_AntiVM` (the CPython runtime does check for an attached debugger) |

This confirms the full pipeline — hashing, PE analysis, entropy, string
extraction, YARA scanning, scoring, and dashboard rendering — works
correctly end-to-end on a real file.

---

## 9. Challenges / Limitations

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

**Current limitations:**

- A full result (PE breakdown, strings, YARA matches) isn't saved
  anywhere — only a summary (hashes, score, verdict) is stored in
  MongoDB Atlas for the History page, and only when `MONGODB_URI` is
  configured; the full dashboard view itself isn't reconstructable
  later.
- PE-specific analysis (sections, imports, exports) is only available
  for Windows executable files; other formats get limited information.
- Free-tier hosting (Render) has an ephemeral filesystem and may "sleep"
  after inactivity, causing a slow first load.
- No user accounts — anyone with the URL can use the analyzer, and the
  History page shows everyone's past analyses (no per-user separation).

---

## 10. Future Enhancements

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

## 11. Conclusion

MallnSight successfully brings together several static malware-analysis
techniques — hashing, PE structure inspection, entropy analysis, string
extraction, and YARA signature matching — into one simple web
application. A user can upload a file and, within seconds, get a clear
risk score, a detailed breakdown of why that score was given, and a
downloadable PDF report, all without the file ever being executed. The
project demonstrates that a lightweight Flask application is enough to
replace a fragmented set of command-line malware-analysis tools for
first-pass triage.

---

## 12. References

1. Flask Documentation — https://flask.palletsprojects.com/
2. `pefile` (PE parsing library) — https://github.com/erocarrera/pefile
3. YARA Documentation — https://yara.readthedocs.io/
4. `yara-python` — https://github.com/VirusTotal/yara-python
5. ReportLab User Guide — https://www.reportlab.com/docs/reportlab-userguide.pdf
6. OWASP File Upload Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
7. Shannon, C.E., "A Mathematical Theory of Communication," Bell System Technical Journal, 1948.
8. Microsoft PE/COFF Specification — https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
9. Render Documentation — https://render.com/docs
10. Waitress WSGI Server — https://docs.pylonsproject.org/projects/waitress/

---

*See [USER_GUIDE.md](USER_GUIDE.md) for client-side how-to instructions
and [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for developer-side setup
and contribution documentation.*
