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
| **Cloud Analysis History** | Optional — every analysis summary (hash, score, verdict, timestamp) is saved to a MongoDB Atlas cluster and browsable on the `/history` page, so results outlive the ephemeral local `uploads/`/`reports/` folders |

All file analysis runs locally — the uploaded file itself is never sent anywhere. The only thing that leaves the machine is the small analysis *summary* (hashes + score, not the file) stored in MongoDB Atlas, and only if `MONGODB_URI` is configured. Without it, the app works exactly the same, just without history.

---

## Tech Stack

- **Backend:** Python, Flask
- **PE Parsing:** pefile
- **Pattern Matching:** yara-python
- **Cloud Database:** MongoDB Atlas (via `pymongo`) — optional, for analysis history
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
│   ├── report.py                # PDF report generation
│   └── history.py               # MongoDB Atlas cloud history (optional)
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

## Cloud History Setup (Optional — MongoDB Atlas)

The `/history` page stores a summary of every analysis (filename,
hashes, score, verdict, timestamp) in a MongoDB Atlas cloud database.
This is entirely optional — without it, everything else works exactly
the same, just without a history page.

1. Create a free cluster at [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas).
2. Under **Database Access**, create a database user (username + password).
3. Under **Network Access**, allow your IP (or `0.0.0.0/0` for quick testing).
4. Click **Connect → Drivers** and copy the connection string, e.g.:
   `mongodb+srv://<user>:<password>@<cluster-host>/?retryWrites=true&w=majority`
5. Copy `.env.example` to `.env` and paste the connection string into `MONGODB_URI`:

```bash
cp .env.example .env
```

```env
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster-host>/?retryWrites=true&w=majority
```

The app loads `.env` automatically on startup (via `python-dotenv`). If
`MONGODB_URI` is missing or unreachable, `/history` simply shows an
"unavailable" message instead of failing.

---

## Usage

1. Go to `/upload`.
2. Drag and drop, or browse, a file to analyze (`.exe`, `.dll`, `.sys`, `.msi`, `.zip`, `.apk`, `.pdf`, `.docx`, `.bin`).
3. View the generated investigation dashboard: risk score, hashes, PE breakdown, entropy chart, suspicious strings, and YARA matches.
4. Download the findings as a PDF report.
5. Check `/history` to see a log of past analyses (if MongoDB Atlas is configured).

Uploaded files are size-limited to 100 MB and stored under a randomly generated filename to avoid collisions.

---

## Deployment

MallnSight ships ready to deploy on [Render](https://render.com)'s free tier:

- The repo includes a `Procfile` (`waitress-serve --host=0.0.0.0 --port=$PORT app:app`) and a `runtime.txt` pinning Python 3.12.
- On Render: **New → Web Service** → connect this GitHub repo → Build Command `pip install -r requirements.txt` → the Start Command is picked up automatically from the `Procfile`.
- The free tier's filesystem is ephemeral — uploaded files and generated reports won't persist across restarts, which is expected for a stateless demo deployment.

### Enabling `/history` on Render

`/history` works locally as soon as `.env` is set up, but **it does not
automatically carry over to your deployed Render service** — Render
never reads your local `.env` file (which is gitignored and never
pushed). You must set the same variable directly in Render:

1. Open [dashboard.render.com](https://dashboard.render.com) → your MallnSight web service.
2. Go to the **Environment** tab.
3. Add **`MONGODB_URI`** with your Atlas connection string as the value.
4. (Optional) Add **`MONGODB_DB`** = `mallnsight`.
5. Save — Render redeploys automatically with the new variables.
6. In MongoDB Atlas → **Network Access**, make sure `0.0.0.0/0` (allow
   from anywhere) is added, since Render's free tier doesn't use a fixed
   outbound IP — without this, Atlas will refuse Render's connections
   even with the correct credentials.

Until these steps are done on Render specifically, `/history` will show
"unavailable" on the live site even though it works locally — this is
expected, not a bug.

---

## Extending the YARA Rule Set

Drop additional `.yar` files into [`yara_rules/`](yara_rules/) — they are compiled and scanned automatically on the next analysis request. Each rule should set a `severity` meta field (`HIGH`, `MEDIUM`, or `LOW`), which feeds directly into the risk score.

---

## Disclaimer

MallnSight performs **static** analysis only — it does not execute or detonate uploaded files. It is intended for educational and authorized security research/testing purposes. Always handle suspicious files in accordance with your organization's security policy.

---

## License

This project does not currently declare a license. All rights reserved unless stated otherwise by the repository owner.
