# MallnSight

**Static Malware Analysis & Threat Intelligence Platform**

MallnSight is a Flask-based web application for performing **offline, static analysis** of suspicious files. It never executes the uploaded file — it inspects hashes, PE structure, entropy, embedded strings, and YARA signatures to produce a risk score and a downloadable PDF investigation report.

> A VivarX Project

---

## Features

| Capability | Description |
|---|---|
| **Hashing** | MD5, SHA1, SHA256 of the uploaded file |
| **File Metadata** | Filename, size, extension, MIME type |
| **PE Analysis** | Architecture, compile timestamp, entry point, image base, sections (with per-section entropy), imports, exports — via [`pefile`](https://github.com/erocarrera/pefile) |
| **Entropy Analysis** | Whole-file Shannon entropy with a packed/encrypted likelihood verdict |
| **String Extraction** | ASCII + UTF-16LE printable strings, with automatic flagging of suspicious indicators (process injection APIs, dynamic API resolution, command interpreters, registry persistence, URLs, IPs, anti-debug/anti-VM checks) |
| **YARA Scanning** | Bundled rule set detecting process injection, dynamic loading, command execution, anti-debug/anti-VM behavior, and high-entropy packing |
| **Risk Scoring** | Combines entropy, YARA matches, and suspicious indicators into a 0–100 score and verdict (`CLEAN`, `LOW RISK`, `SUSPICIOUS`, `HIGH RISK`) |
| **PDF Reports** | One-click downloadable investigation report via [`reportlab`](https://www.reportlab.com/) |

All analysis runs locally — no file or hash is ever sent to a third-party service.

---

## Tech Stack

- **Backend:** Python, Flask
- **PE Parsing:** pefile
- **Pattern Matching:** yara-python
- **PDF Generation:** reportlab
- **Frontend:** Jinja2, Bootstrap 5, vanilla JS

---

## Project Structure

```
mallnsight/
├── app.py                     # Flask routes & request handling
├── analysis/
│   ├── hash.py                # MD5 / SHA1 / SHA256
│   ├── metadata.py             # File info (size, MIME, extension)
│   ├── pe_analysis.py          # PE header / sections / imports / exports
│   ├── entropy.py              # Shannon entropy
│   ├── strings.py              # String extraction + suspicious indicators
│   ├── yara_scan.py            # YARA rule compilation & scanning
│   ├── scoring.py               # Risk score & verdict
│   └── report.py                # PDF report generation
├── yara_rules/                 # Bundled .yar rule files
├── templates/                   # Jinja2 pages (home, upload, dashboard, ...)
├── static/                      # CSS / JS / assets
├── uploads/                      # Uploaded files (gitignored, runtime only)
└── reports/                       # Generated PDF reports (gitignored, runtime only)
```

---

## Getting Started

### Prerequisites

- Python 3.10+ (3.11/3.12 recommended for prebuilt `yara-python` wheels)
- On Windows, building `yara-python` from source requires the
  [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

### Setup

```bash
git clone git@github.com:vibushasatheeshkumar/mallnsight.git
cd mallnsight

python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### Run

```bash
python app.py
```

The app starts at **http://127.0.0.1:5000**. By default the Flask debug server runs with debug mode off; set `FLASK_DEBUG=1` to enable it during development.

```bash
# Windows (PowerShell)
$env:FLASK_DEBUG="1"; python app.py

# macOS/Linux
FLASK_DEBUG=1 python app.py
```

---

## Usage

1. Go to `/upload`.
2. Drag and drop, or browse, a file to analyze (`.exe`, `.dll`, `.sys`, `.msi`, `.zip`, `.apk`, `.pdf`, `.docx`, `.bin`).
3. View the generated investigation dashboard: risk score, hashes, PE breakdown, entropy chart, suspicious strings, and YARA matches.
4. Download the findings as a PDF report.

Uploaded files are size-limited to 100 MB and stored under a randomly generated filename to avoid collisions.

---

## Deployment

MallnSight ships ready to deploy on [Render](https://render.com)'s free tier:

- The repo includes a `Procfile` (`waitress-serve --host=0.0.0.0 --port=$PORT app:app`) and a `runtime.txt` pinning Python 3.12.
- On Render: **New → Web Service** → connect this GitHub repo → Build Command `pip install -r requirements.txt` → the Start Command is picked up automatically from the `Procfile`.
- The free tier's filesystem is ephemeral — uploaded files and generated reports won't persist across restarts, which is expected for a stateless demo deployment.

---

## Extending the YARA Rule Set

Drop additional `.yar` files into [`yara_rules/`](yara_rules/) — they are compiled and scanned automatically on the next analysis request. Each rule should set a `severity` meta field (`HIGH`, `MEDIUM`, or `LOW`), which feeds directly into the risk score.

---

## Disclaimer

MallnSight performs **static** analysis only — it does not execute or detonate uploaded files. It is intended for educational and authorized security research/testing purposes. Always handle suspicious files in accordance with your organization's security policy.

---

## License

This project does not currently declare a license. All rights reserved unless stated otherwise by the repository owner.
