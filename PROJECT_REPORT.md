# MallnSight — Project Documentation

**Static Malware Analysis & Threat Intelligence Platform**

Repository: https://github.com/vibushasatheeshkumar/mallnsight

---

## 1. Objective / Aim

To design and implement a web-based static malware analysis platform that
allows a user to upload a suspicious file and receive an automated,
offline security assessment — covering cryptographic fingerprinting,
executable structure inspection, entropy analysis, string-based indicator
extraction, and signature (YARA) matching — culminating in a quantified
risk score and a downloadable, shareable investigation report, **without
ever executing the file under analysis**.

---

## 2. Introduction

Malicious software ("malware") is most commonly identified through one of
two approaches:

- **Dynamic analysis** — executing the sample in an isolated sandbox and
  observing its runtime behavior.
- **Static analysis** — examining the file's structure, content, and
  metadata *without running it*.

Dynamic analysis is powerful but carries operational risk (the sample
must be detonated somewhere) and requires heavyweight sandbox
infrastructure (VMs, snapshotting, network containment). Static analysis,
by contrast, can be performed safely on commodity hardware and is the
first line of triage used by SOC analysts, malware researchers, and
incident responders before a sample is ever escalated to a sandbox.

MallnSight is a self-contained, locally-hosted tool that automates the
static-analysis triage workflow end-to-end through a simple web
interface, packaging together several techniques that are traditionally
run as separate command-line utilities (`md5sum`, `pefile` scripts,
`strings`, `yara`, entropy calculators) into a single upload-and-go
experience.

---

## 3. Problem Statement

Security analysts and students learning malware analysis face a
recurring set of frictions:

1. **Tool fragmentation** — hashing, PE parsing, string extraction,
   entropy calculation, and YARA scanning are normally separate CLI
   tools, each with different output formats that must be manually
   cross-referenced.
2. **No unified verdict** — none of the individual tools produce a single
   actionable risk score; the analyst must manually synthesize the
   signals.
3. **Unsafe defaults** — many quick-look workflows involve opening the
   file or running it "just to see," which risks accidental execution of
   live malware on the analyst's own machine.
4. **No shareable artifact** — CLI output is rarely packaged into a
   report that can be attached to a ticket or shared with a non-technical
   stakeholder.

**Problem:** there is no lightweight, offline, single-pane-of-glass tool
that takes a raw file as input and produces a structured, scored,
exportable static-analysis report without requiring the analyst to
execute the sample or stitch together multiple command-line tools.

---

## 4. Proposed Solution

MallnSight addresses this by providing:

- A **single upload endpoint** that fans a file out to multiple
  independent analysis modules, each responsible for one technique.
- A **deterministic scoring engine** that combines the output of every
  module into one 0–100 risk score and a four-tier verdict (`CLEAN`,
  `LOW RISK`, `SUSPICIOUS`, `HIGH RISK`).
- A **web dashboard** that visually surfaces every signal (hashes, PE
  metadata, entropy chart, suspicious strings, YARA matches) on one
  screen.
- A **one-click PDF export** of the full findings for sharing/archival.
- **Zero execution** of the uploaded file at any stage — every module
  only *reads* the file's bytes.
- An **extensible YARA rule directory**, so new detection logic can be
  added without touching application code.

---

## 5. System Architecture

MallnSight follows a classic **monolithic server-rendered web
application** architecture — a single Flask process handling both the
HTTP layer and the analysis pipeline, with no external services or
databases required to run it.

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
                        │    (extension allow-list,      │
                        │     100 MB size limit,          │
                        │     UUID-based storage)          │
                        └────────────┬─────────────────────┘
                                     │ delegates to
                                     ▼
              ┌──────────────────────────────────────────────┐
              │                Analysis Engine                  │
              │                (analysis/ package)                │
              │                                                     │
              │  hash.py        → MD5 / SHA1 / SHA256                │
              │  metadata.py    → size, MIME, extension               │
              │  pe_analysis.py → pefile: headers/sections/imports     │
              │  entropy.py     → Shannon entropy (whole file)          │
              │  strings.py     → ASCII/UTF-16LE strings + indicators    │
              │  yara_scan.py   → yara-python against yara_rules/*.yar   │
              │  scoring.py     → combines all signals → score + verdict  │
              │  report.py      → reportlab → PDF investigation report     │
              └───────────────────────┬──────────────────────────────────┘
                                      │ writes
                          ┌───────────┴────────────┐
                          ▼                         ▼
                   uploads/<uuid>.ext        reports/<name>_<ts>.pdf
                  (ephemeral, gitignored)    (ephemeral, gitignored)
```

**Key architectural decisions:**

- **Stateless, file-based storage.** Uploaded files and generated reports
  are written to local disk (`uploads/`, `reports/`) under randomly
  generated names. There is no database — every analysis result is
  rendered directly into the response and also baked into a PDF; nothing
  is queried back out later. This keeps the system trivially deployable
  (no DB provisioning) at the cost of not retaining analysis history.
- **Module independence.** Each file in `analysis/` is a pure function
  (file path in → structured dict out) with no shared mutable state,
  which makes the pipeline easy to test in isolation and easy to extend
  with new modules.
- **Graceful degradation.** `yara_scan.py` detects at import time whether
  `yara-python` is installed; if not, it returns an "unavailable" result
  instead of crashing the request, so the rest of the pipeline still
  produces a usable report.

---

## 6. Database Design

**Not required for the current scope**, and intentionally omitted.

MallnSight's request/response cycle is fully self-contained: a file is
uploaded, analyzed in-memory/on-disk, rendered into a dashboard, and
optionally exported to PDF — all within a single HTTP request-response
pair. No analysis result needs to be looked up by a *different* later
request, so there is no entity that benefits from persistent, queryable
storage today.

**If "Future Enhancements" (Section 9) such as analysis history,
multi-user accounts, or a searchable hash database were implemented**, the
following minimal relational schema would be introduced:

| Table | Key Columns | Purpose |
|---|---|---|
| `samples` | `id`, `sha256` (unique), `filename`, `size`, `mime`, `uploaded_at` | One row per unique uploaded file (de-duplicated by hash) |
| `analyses` | `id`, `sample_id` (FK), `risk_score`, `verdict`, `entropy`, `created_at` | One row per analysis run against a sample |
| `yara_matches` | `id`, `analysis_id` (FK), `rule_name`, `severity` | Normalized YARA hits per analysis |
| `suspicious_strings` | `id`, `analysis_id` (FK), `category`, `value` | Normalized flagged strings per analysis |
| `users` | `id`, `email`, `password_hash`, `created_at` | Only needed if multi-user auth is added |

This would use SQLite for a single-instance deployment or PostgreSQL for
a multi-instance one, via SQLAlchemy as the ORM layer (consistent with
Flask's ecosystem).

---

## 7. Workflow

End-to-end request flow for a single analysis:

1. **Upload** — User submits a file via `/upload` to the `/analyze`
   endpoint (`multipart/form-data`, POST only).
2. **Validation** — `app.py` checks the filename is non-empty, sanitizes
   it with `secure_filename`, verifies the extension against an
   allow-list (`.exe .dll .sys .msi .zip .apk .pdf .docx .bin`), and
   enforces a 100 MB request-size cap.
3. **Storage** — The file is saved under `uploads/<uuid4>.<ext>` — a
   randomly generated name, decoupled from the user-supplied filename, to
   avoid collisions and path traversal.
4. **Pipeline execution** (sequential, all on the same request thread):
   - `calculate_hashes()` → MD5/SHA1/SHA256
   - `get_metadata()` → size, extension, MIME
   - `analyze_pe()` → PE header/sections/imports/exports (or an `error`
     key if the file isn't a valid PE)
   - `analyze_entropy()` → whole-file Shannon entropy + verdict
   - `extract_strings()` → printable strings + flagged suspicious ones
   - `scan_file()` → YARA rule matches (or "unavailable" if YARA isn't
     installed)
5. **Scoring** — `calculate_score()` combines entropy, YARA severities,
   suspicious-string categories, and high-entropy PE sections into a
   single 0–100 score and a verdict string.
6. **Reporting** — `generate_report()` renders every result above into a
   PDF via `reportlab`, saved to `reports/<name>_<timestamp>.pdf`; a
   one-time download ID is minted and mapped to that path in memory.
7. **Response** — `dashboard.html` is rendered with every result object,
   showing the verdict, hashes (with copy-to-clipboard), PE breakdown,
   entropy bars, suspicious string pills, YARA matches table, and a
   "Download PDF Report" button (`/download/<id>`).

---

## 8. Technical Implementation

### 8.1 Backend

- **Framework:** Flask 3.x, served by Werkzeug's dev server locally and
  by `waitress` (`waitress-serve`) in production/Render deployment.
- **Routing:** `app.py` exposes `/`, `/about`, `/features`, `/upload`,
  `/dashboard`, `/contact`, `POST /analyze`, and `GET /download/<id>`.
- **File handling:** `werkzeug.utils.secure_filename` + a hand-rolled
  extension allow-list + `MAX_CONTENT_LENGTH` config for upload
  hardening.

### 8.2 Analysis Modules

| Module | Library | Output |
|---|---|---|
| `hash.py` | `hashlib` (stdlib) | MD5, SHA1, SHA256 (chunked read, 4 KB buffer) |
| `metadata.py` | `os`, `mimetypes` (stdlib) | filename, size (KB), extension, MIME |
| `pe_analysis.py` | `pefile` | architecture, compile time, entry point, image base, sections (with per-section entropy), imports, exports |
| `entropy.py` | `math`, `collections.Counter` (stdlib) | Shannon entropy formula `H = -Σ p(x)·log2(p(x))` over the whole file |
| `strings.py` | `re` (stdlib) | ASCII (`[\x20-\x7e]{4,}`) and UTF-16LE string extraction, regex-matched against 9 suspicious-indicator categories (process injection APIs, dynamic loading, command interpreters, registry persistence, URLs, IPs, anti-debug/anti-VM) |
| `yara_scan.py` | `yara-python` | Compiles all `.yar` files in `yara_rules/` once and caches the compiled ruleset; returns rule name, description, and severity per match |
| `scoring.py` | — | Weighted sum: entropy thresholds (+15/+30), YARA severity (`HIGH`+25, `MEDIUM`+15, `LOW`+5 each), suspicious string categories (+8 each), high-entropy PE sections (+10), capped at 100, mapped to a 4-tier verdict |
| `report.py` | `reportlab` | `SimpleDocTemplate`/`Platypus` PDF with styled tables mirroring the dashboard |

### 8.3 YARA Rule Set (`yara_rules/suspicious_indicators.yar`)

Five rules, each tagged with a `severity` meta field consumed directly by
the scoring engine:

- `Suspicious_Process_Injection` — `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`, etc. (HIGH)
- `Suspicious_Dynamic_API_Resolution` — `LoadLibraryA/W` + `GetProcAddress` (MEDIUM)
- `Suspicious_Command_Execution` — `cmd.exe`, `powershell.exe`, `WinExec`, etc. (MEDIUM)
- `Suspicious_AntiDebug_AntiVM` — `IsDebuggerPresent`, `VMware`, `VBox`, etc. (MEDIUM)
- `Packed_File_High_Entropy` — uses YARA's built-in `math.entropy()` module, flags files ≥ 7.5 bits/byte (MEDIUM)

### 8.4 Frontend

- Server-rendered Jinja2 templates extending a shared `base.html` (navbar,
  footer, Bootstrap 5 + Tabler Icons CDN includes).
- Custom dark "enterprise" theme defined via CSS variables in
  `static/css/style.css` (`--bg`, `--surface`, `--primary`, etc.).
- Vanilla JS (`static/js/main.js`) for: navbar scroll-shrink effect,
  `IntersectionObserver`-driven scroll-reveal with staggered easing,
  drag-and-drop file selection feedback, and clipboard copy buttons —
  with `prefers-reduced-motion` respected throughout.

### 8.5 Testing & CI

- `tests/test_app.py` — pytest smoke suite using Flask's test client:
  every static route returns 200; `/analyze` correctly rejects missing
  files (400), GET requests (405), and disallowed extensions (400); a
  real PE file (`python.exe`) is analyzed end-to-end and asserted to
  contain a risk score.
- `.github/workflows/ci.yml` — GitHub Actions matrix running the suite on
  Python 3.11 and 3.12 for every push/PR to `main`.

### 8.6 Deployment

- `Procfile`: `web: waitress-serve --host=0.0.0.0 --port=$PORT app:app`
- `runtime.txt`: pins Python 3.12.7
- Designed for Render's free tier — connect the GitHub repo, Render
  builds from `requirements.txt` and starts via the `Procfile`
  automatically.

---

## 9. Challenges Faced

1. **`yara-python` has no prebuilt wheel for brand-new Python versions
   on Windows.** Building it from source required installing the
   Microsoft C++ Build Tools, and even with the compiler present,
   `setuptools`' MSVC auto-detection failed until `DISTUTILS_USE_SDK=1`
   and `MSSdk=1` were explicitly set in the build environment — a
   known but non-obvious workaround.
2. **Silent file re-encoding.** `requirements.txt` was originally saved
   as UTF-16LE (likely by a Windows editor), which made every line
   unparsable to `pip` (`Invalid requirement: 'b\x00l\x00i\x00n\x00k...'`)
   despite looking correct when viewed normally. The file had to be
   rewritten via direct UTF-8 byte output rather than a text-editor save
   to fix it permanently.
3. **CI failing on a dependency never even used.** `python-magic-bin`
   (Windows-only wheels, no Linux/manylinux build) was present in
   `requirements.txt` purely as dead weight from an unrelated environment
   snapshot, and silently broke every GitHub Actions run on
   `ubuntu-latest` until it was identified and removed.
4. **Dead template code silently never rendering.** Both `dashboard.html`
   and `home.html` contained large blocks of markup placed *after*
   `{% endblock %}` — Jinja simply discards content outside the block it
   extends, so this code looked present in the file but never reached
   the browser. The original dashboard also displayed hardcoded mock
   data instead of the real `pe_info`/`hashes`/`metadata` passed from
   Flask, which wasn't obvious until the variables were traced end to
   end.
5. **Jinja's template caching in non-debug mode.** While iterating on the
   UI, a long-running dev server process kept serving stale (in one case,
   empty) template output even after the files on disk were corrected,
   because Flask only auto-reloads templates when `debug=True`. Multiple
   leftover server processes from earlier in development were also found
   bound to the same port, compounding the confusion until all stale
   processes were identified and killed.
6. **Framer Motion is React-only.** A request for "Framer Motion"-style
   animation had to be reinterpreted for a server-rendered Jinja/vanilla-JS
   stack — solved with equivalent CSS `cubic-bezier` easing and staggered
   `IntersectionObserver` reveals rather than the literal library.

---

## 10. Future Enhancements

- **Non-PE format support** — first-class analysis for ZIP/APK (archive
  listing, manifest parsing), PDF (embedded JavaScript/object detection),
  and Office documents (macro extraction), rather than only PE files.
- **Analysis history & persistence** — introduce the database schema
  outlined in Section 6 to let users revisit past analyses by hash.
- **Multi-user accounts & authentication** — per-user upload history and
  access control, useful for team/SOC usage.
- **Optional sandboxed dynamic analysis** — integrate with an isolated
  detonation environment for a deeper, opt-in "Run it safely" tier,
  clearly separated from the static-only default.
- **Threat-intel enrichment** — optional, explicitly opt-in cross-check of
  computed hashes against external services (e.g. VirusTotal) for known-
  sample correlation.
- **Malware family classification** — apply ML/clustering over
  string/import features to suggest a likely malware family rather than
  just a numeric score.
- **Containerization** — a `Dockerfile` for fully reproducible deployment
  independent of host OS/Python version quirks (directly motivated by the
  Windows-build pain documented in Section 9).
- **Rate limiting & abuse protection** — if exposed publicly, add request
  throttling around `/analyze` given it's CPU/IO-bound per upload.

---

## 11. Conclusion

MallnSight successfully consolidates the static malware analysis
workflow — hashing, PE structure inspection, entropy analysis, string/
indicator extraction, and YARA signature matching — into a single,
offline, browser-based tool that produces both an interactive dashboard
and a shareable PDF report, all without ever executing the file under
investigation. The project demonstrates that a lightweight, dependency-
conscious Flask application is sufficient to replace a fragmented set of
command-line utilities for first-pass triage, while remaining easy to
extend (new YARA rules, new analysis modules) and easy to deploy
(a single `Procfile`-driven web service with no required database).

---

## 12. References

1. Flask Documentation — https://flask.palletsprojects.com/
2. `pefile` — PE parsing library for Python — https://github.com/erocarrera/pefile
3. YARA Documentation — https://yara.readthedocs.io/
4. `yara-python` — https://github.com/VirusTotal/yara-python
5. ReportLab User Guide — https://www.reportlab.com/docs/reportlab-userguide.pdf
6. OWASP File Upload Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
7. Shannon, C.E., "A Mathematical Theory of Communication," *Bell System Technical Journal*, 1948.
8. Microsoft PE/COFF Specification — https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
9. Render Documentation — https://render.com/docs
10. Waitress WSGI Server — https://docs.pylonsproject.org/projects/waitress/
