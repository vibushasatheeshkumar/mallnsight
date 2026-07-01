# Solution File — MallnSight

**Project:** MallnSight — Static Malware Analysis & Threat Intelligence Platform
**Repository:** https://github.com/vibushasatheeshkumar/mallnsight

---

## Overview

MallnSight is a Python-based web application. It does not compile to a
native binary — the executable entry point is a Python script (`app.py`)
that launches a local web server. All source files are plain text and
can be opened, read, and modified directly.

---

## Executable Files

These are the files that are directly run to start or use the system:

| File | How to Run | Purpose |
|---|---|---|
| `app.py` | `python app.py` | **Main entry point** — starts the Flask web server on `http://127.0.0.1:5000` |
| `generate_source_pdf.py` | `python generate_source_pdf.py` | Generates the full source code listing as a PDF |

---

## Source Code Files

### Backend

| File | Description |
|---|---|
| `app.py` | Flask application — all HTTP routes, upload validation, analysis pipeline orchestration, PDF download, and MongoDB history endpoint |

### Analysis Modules (`analysis/`)

| File | Description |
|---|---|
| `analysis/hash.py` | Computes MD5, SHA1, and SHA256 hashes of the uploaded file using chunked reads |
| `analysis/metadata.py` | Extracts filename, file size (KB), extension, and MIME type |
| `analysis/pe_analysis.py` | Parses Windows PE structure (architecture, compile time, entry point, sections, imports, exports) using `pefile` |
| `analysis/entropy.py` | Calculates Shannon entropy of the whole file to detect packing or encryption |
| `analysis/strings.py` | Extracts ASCII and UTF-16LE printable strings; flags suspicious indicators (injection APIs, URLs, IPs, registry keys, anti-debug checks) |
| `analysis/yara_scan.py` | Compiles and scans against all YARA rules in `yara_rules/`; returns rule name, description, and severity per match |
| `analysis/scoring.py` | Combines entropy, YARA matches, and suspicious string signals into a single 0–100 risk score and verdict |
| `analysis/report.py` | Generates a formatted PDF investigation report using `reportlab` |
| `analysis/history.py` | Connects to MongoDB Atlas (optional) to save and retrieve a summary of each analysis for the `/history` page |

### YARA Rules (`yara_rules/`)

| File | Description |
|---|---|
| `yara_rules/suspicious_indicators.yar` | Five bundled YARA rules: process injection, dynamic API resolution, command execution, anti-debug/anti-VM, and high-entropy packing |

### Templates (`templates/`)

| File | Description |
|---|---|
| `templates/base.html` | Shared layout — navbar, footer, Bootstrap 5 + Tabler Icons CDN |
| `templates/home.html` | Landing page with hero section, feature cards, and workflow |
| `templates/features.html` | Full feature listing page |
| `templates/about.html` | Documentation page with tech stack, project structure, and setup guide |
| `templates/upload.html` | File upload form with drag-and-drop support |
| `templates/dashboard.html` | Analysis results dashboard — verdict, hashes, PE analysis, entropy bars, suspicious strings, YARA matches, PDF download |
| `templates/history.html` | Cloud history page listing past analyses from MongoDB Atlas |
| `templates/contact.html` | Contact page with email, GitHub, and LinkedIn links |

### Static Assets (`static/`)

| File | Description |
|---|---|
| `static/css/style.css` | Custom dark-theme enterprise CSS using CSS variables, responsive breakpoints, and animation keyframes |
| `static/js/main.js` | Vanilla JavaScript — navbar scroll effect, scroll-reveal animations, drag-and-drop feedback, clipboard copy |

### Tests (`tests/`)

| File | Description |
|---|---|
| `tests/test_app.py` | `pytest` smoke test suite — 11 test cases covering all routes, upload validation, cloud history graceful degradation, and end-to-end analysis |

### Configuration & Deployment

| File | Description |
|---|---|
| `requirements.txt` | Production Python dependencies |
| `requirements-dev.txt` | Development dependencies (adds `pytest`) |
| `Procfile` | Render deployment start command: `waitress-serve --host=0.0.0.0 --port=$PORT app:app` |
| `runtime.txt` | Pinned Python version for Render deployment |
| `.env.example` | Template for local environment variables (`MONGODB_URI`, `MONGODB_DB`, `FLASK_DEBUG`) |
| `.github/workflows/ci.yml` | GitHub Actions CI — runs the test suite on Python 3.11 and 3.12 on every push |

---

## How to Run the Solution

### Step 1 — Install dependencies

```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux

pip install -r requirements.txt
```

### Step 2 — Configure environment (optional — for cloud history)

```bash
copy .env.example .env      # Windows
cp .env.example .env        # macOS / Linux
```

Open `.env` and fill in your MongoDB Atlas connection string:

```
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?appName=...
MONGODB_DB=mallnsight
```

### Step 3 — Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## Project Statistics

| Metric | Value |
|---|---|
| Total source files | 23 |
| Total lines of code | ~3,200 (Python + HTML + CSS + JS) |
| Python modules | 10 |
| HTML templates | 8 |
| YARA detection rules | 5 |
| Automated tests | 11 |
| PDF generated | `MallnSight_SourceCode.pdf` (128 pages) |

---

## Full Source Code

The complete source code is available in two forms:

- **GitHub Repository:** https://github.com/vibushasatheeshkumar/mallnsight
- **Printed PDF:** `MallnSight_SourceCode.pdf` — all source files in
  order, Times-Roman font, 1.5 line spacing, generated by
  `generate_source_pdf.py`
