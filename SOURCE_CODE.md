# MallnSight — Source Code

**Static Malware Analysis & Threat Intelligence Platform**
Repository: https://github.com/vibushasatheeshkumar/mallnsight

---

## Backend

### app.py

```python
import os
import uuid

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, render_template, request, send_file, abort
from werkzeug.utils import secure_filename

from analysis.hash import calculate_hashes
from analysis.metadata import get_metadata
from analysis.pe_analysis import analyze_pe
from analysis.entropy import analyze_entropy
from analysis.strings import extract_strings
from analysis.yara_scan import scan_file
from analysis.scoring import calculate_score
from analysis.report import generate_report
from analysis.history import save_analysis, get_recent_analyses, is_available, get_connection_error


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
REPORTS_FOLDER = "reports"

ALLOWED_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".msi", ".zip", ".apk", ".pdf", ".docx", ".bin"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB

# Create uploads/reports folders if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# In-memory map of generated PDF reports, keyed by a one-time download id.
_generated_reports = {}


def is_allowed_file(filename):
    extension = os.path.splitext(filename)[1].lower()
    return extension in ALLOWED_EXTENSIONS


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/features")
def features():
    return render_template("features.html")


@app.route("/upload")
def upload():
    return render_template("upload.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    if "file" not in request.files:
        return "No file uploaded.", 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return "No file selected.", 400

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename:
        return "Invalid filename.", 400

    if not is_allowed_file(original_filename):
        return "File type is not supported.", 400

    extension = os.path.splitext(original_filename)[1].lower()
    stored_filename = f"{uuid.uuid4().hex}{extension}"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)

    uploaded_file.save(file_path)

    # File Information
    metadata = get_metadata(file_path)
    metadata["name"] = original_filename

    # File Hashes
    hashes = calculate_hashes(file_path)

    # PE Analysis
    pe_info = analyze_pe(file_path)

    # Entropy Analysis
    entropy_info = analyze_entropy(file_path)

    # Suspicious Strings
    strings_info = extract_strings(file_path)

    # YARA Scan
    yara_info = scan_file(file_path)

    # Risk Scoring
    score_info = calculate_score(
        entropy_info=entropy_info,
        yara_info=yara_info,
        strings_info=strings_info,
        pe_info=pe_info
    )

    report_path = generate_report(
        metadata, hashes, pe_info, entropy_info, strings_info, yara_info, score_info
    )

    download_id = uuid.uuid4().hex
    _generated_reports[download_id] = report_path

    # Cloud history (MongoDB Atlas) — non-fatal if not configured
    save_analysis(metadata, hashes, score_info)

    return render_template(
        "dashboard.html",
        metadata=metadata,
        hashes=hashes,
        pe_info=pe_info,
        entropy_info=entropy_info,
        strings_info=strings_info,
        yara_info=yara_info,
        score_info=score_info,
        download_id=download_id
    )


@app.route("/history")
def history():
    return render_template(
        "history.html",
        available=is_available(),
        error=get_connection_error(),
        records=get_recent_analyses()
    )


@app.route("/download/<download_id>")
def download_report(download_id):
    report_path = _generated_reports.get(download_id)

    if not report_path or not os.path.exists(report_path):
        abort(404)

    return send_file(report_path, as_attachment=True, download_name="MallnSight_Report.pdf")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
```

---

## Analysis Modules

### analysis/hash.py

```python
import hashlib

def calculate_hashes(file_path):
    """
    Calculate MD5, SHA1 and SHA256 hashes of a file.
    """

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:

        while True:

            chunk = f.read(4096)

            if not chunk:
                break

            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }
```

### analysis/metadata.py

```python
import os
import mimetypes

def get_metadata(file_path):

    file_size = os.path.getsize(file_path)

    file_name = os.path.basename(file_path)

    mime_type = mimetypes.guess_type(file_path)[0]

    extension = os.path.splitext(file_name)[1]

    return {
        "name": file_name,
        "size": round(file_size / 1024, 2),
        "extension": extension,
        "mime": mime_type
    }
```

### analysis/pe_analysis.py

```python
import pefile
import os
from datetime import datetime


def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)

        info = {}

        # Architecture
        machine = pe.FILE_HEADER.Machine

        architectures = {
            0x14c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x1c0: "ARM",
            0xaa64: "ARM64"
        }

        info["architecture"] = architectures.get(
            machine,
            hex(machine)
        )

        # Compile Time
        info["compile_time"] = datetime.utcfromtimestamp(
            pe.FILE_HEADER.TimeDateStamp
        ).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Entry Point
        info["entry_point"] = hex(
            pe.OPTIONAL_HEADER.AddressOfEntryPoint
        )

        # Image Base
        info["image_base"] = hex(
            pe.OPTIONAL_HEADER.ImageBase
        )

        # Number of Sections
        info["number_of_sections"] = pe.FILE_HEADER.NumberOfSections

        # Section Names
        sections = []

        for section in pe.sections:
            sections.append({
                "name": section.Name.decode(errors="ignore").strip("\x00"),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 2)
            })

        info["sections"] = sections

        # Imports
        imports = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")

                for imp in entry.imports:
                    imports.append({
                        "dll": dll,
                        "function": (
                            imp.name.decode(errors="ignore")
                            if imp.name
                            else f"Ordinal {imp.ordinal}"
                        )
                    })

        info["imports"] = imports

        # Exports
        exports = []

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append(
                    exp.name.decode(errors="ignore")
                    if exp.name
                    else f"Ordinal {exp.ordinal}"
                )

        info["exports"] = exports

        return info

    except Exception as e:
        return {
            "error": str(e)
        }
```

### analysis/entropy.py

```python
import math
from collections import Counter


def calculate_entropy(data):
    """
    Shannon entropy of a byte string, in bits per byte (0.0 - 8.0).
    """

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def analyze_entropy(file_path):
    """
    Compute overall file entropy and classify how likely the file is
    to be packed/encrypted/compressed.
    """

    with open(file_path, "rb") as f:
        data = f.read()

    entropy = round(calculate_entropy(data), 2)

    if entropy >= 7.5:
        verdict = "Very High (likely packed/encrypted)"
    elif entropy >= 6.5:
        verdict = "High (possibly compressed/packed)"
    elif entropy >= 4.0:
        verdict = "Normal"
    else:
        verdict = "Low (mostly repetitive/plain data)"

    return {
        "entropy": entropy,
        "max_entropy": 8.0,
        "verdict": verdict
    }
```

### analysis/strings.py

```python
import re

MIN_LENGTH = 4
MAX_STRINGS = 500

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LENGTH)
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LENGTH)

SUSPICIOUS_PATTERNS = {
    "Process Injection API": re.compile(
        r"\b(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|"
        r"NtUnmapViewOfSection|QueueUserAPC|SetThreadContext)\b"
    ),
    "Dynamic Loading API": re.compile(
        r"\b(LoadLibraryA|LoadLibraryW|GetProcAddress|LdrLoadDll)\b"
    ),
    "Execution API": re.compile(
        r"\b(WinExec|ShellExecuteA|ShellExecuteW|CreateProcessA|CreateProcessW)\b"
    ),
    "Memory API": re.compile(r"\b(VirtualAlloc|VirtualProtect|HeapCreate)\b"),
    "Command Interpreter": re.compile(
        r"\b(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|rundll32\.exe|mshta\.exe)\b",
        re.IGNORECASE,
    ),
    "Persistence / Registry": re.compile(
        r"(HKEY_[A-Z_]+|\\CurrentVersion\\Run|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)"
    ),
    "URL": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "IP Address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "Anti-Debug / Anti-VM": re.compile(
        r"\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|vmware|virtualbox|sandboxie)\b",
        re.IGNORECASE,
    ),
}


def extract_strings(file_path, min_length=MIN_LENGTH, max_strings=MAX_STRINGS):
    """
    Extract printable ASCII and UTF-16LE strings from a file and flag
    any that match known-suspicious patterns.
    """

    with open(file_path, "rb") as f:
        data = f.read()

    found = []

    for match in _ASCII_RE.finditer(data):
        found.append(match.group().decode("ascii", errors="ignore"))

    for match in _WIDE_RE.finditer(data):
        found.append(match.group().decode("utf-16le", errors="ignore"))

    unique_strings = list(dict.fromkeys(found))

    suspicious = []

    for category, pattern in SUSPICIOUS_PATTERNS.items():
        for s in unique_strings:
            m = pattern.search(s)
            if m:
                suspicious.append({
                    "category": category,
                    "value": m.group()
                })

    unique_suspicious = list(
        {(s["category"], s["value"]): s for s in suspicious}.values()
    )

    return {
        "total_strings": len(unique_strings),
        "strings": unique_strings[:max_strings],
        "suspicious": unique_suspicious
    }
```

### analysis/yara_scan.py

```python
import glob
import os

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "yara_rules")

_compiled_rules = None
_compile_error = None


def _load_rules():
    global _compiled_rules, _compile_error

    if _compiled_rules is not None or _compile_error is not None:
        return

    rule_files = glob.glob(os.path.join(RULES_DIR, "*.yar"))

    if not rule_files:
        _compile_error = "No YARA rule files found."
        return

    try:
        filepaths = {
            f"rule_{i}": path for i, path in enumerate(rule_files)
        }
        _compiled_rules = yara.compile(filepaths=filepaths)
    except yara.Error as e:
        _compile_error = str(e)


def scan_file(file_path):
    """
    Scan a file against the bundled YARA rules.
    Returns a list of {rule, description, severity} matches.
    """

    if not YARA_AVAILABLE:
        return {
            "available": False,
            "error": "yara-python is not installed.",
            "matches": []
        }

    _load_rules()

    if _compile_error:
        return {
            "available": False,
            "error": _compile_error,
            "matches": []
        }

    try:
        raw_matches = _compiled_rules.match(file_path)
    except yara.Error as e:
        return {
            "available": False,
            "error": str(e),
            "matches": []
        }

    matches = []

    for m in raw_matches:
        matches.append({
            "rule": m.rule,
            "description": m.meta.get("description", ""),
            "severity": m.meta.get("severity", "LOW")
        })

    return {
        "available": True,
        "error": None,
        "matches": matches
    }
```

### analysis/scoring.py

```python
SEVERITY_WEIGHTS = {
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5
}


def calculate_score(entropy_info=None, yara_info=None, strings_info=None, pe_info=None):
    """
    Combine entropy, YARA matches and suspicious strings/imports into a
    single 0-100 risk score with a human-readable verdict.
    """

    score = 0
    reasons = []

    if entropy_info:
        entropy = entropy_info.get("entropy", 0)

        if entropy >= 7.5:
            score += 30
            reasons.append(f"Very high overall entropy ({entropy})")
        elif entropy >= 6.5:
            score += 15
            reasons.append(f"Elevated overall entropy ({entropy})")

    if yara_info and yara_info.get("matches"):
        for match in yara_info["matches"]:
            weight = SEVERITY_WEIGHTS.get(match.get("severity", "LOW"), 5)
            score += weight
            reasons.append(f"YARA rule matched: {match['rule']}")

    if strings_info and strings_info.get("suspicious"):
        categories = {s["category"] for s in strings_info["suspicious"]}

        for category in categories:
            score += 8
            reasons.append(f"Suspicious indicator found: {category}")

    if pe_info and not pe_info.get("error"):
        for section in pe_info.get("sections", []):
            if section.get("entropy", 0) >= 7.5:
                score += 10
                reasons.append(f"High entropy PE section: {section['name']}")
                break

    score = min(score, 100)

    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    elif score >= 15:
        verdict = "LOW RISK"
    else:
        verdict = "CLEAN"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }
```

### analysis/report.py

```python
import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


def _table(rows, col_widths=None):
    table = Table(rows, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2128")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363D")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F4F6")]),
    ]))
    return table


def generate_report(metadata, hashes, pe_info, entropy_info, strings_info, yara_info, score_info):
    """
    Render the analysis results into a PDF report and return its file path.
    """

    os.makedirs(REPORTS_DIR, exist_ok=True)

    base_name = os.path.splitext(metadata.get("name", "report"))[0]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    out_path = os.path.join(REPORTS_DIR, f"{base_name}_{timestamp}.pdf")

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("MallnSight Static Analysis Report", styles["Title"]))
    story.append(Paragraph(
        datetime.now(timezone.utc).strftime("Generated %Y-%m-%d %H:%M UTC"),
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph(
        f"Verdict: {score_info['verdict']} (Risk score: {score_info['score']}/100)",
        styles["Heading2"]
    ))

    if score_info.get("reasons"):
        for reason in score_info["reasons"]:
            story.append(Paragraph(f"- {reason}", styles["Normal"]))

    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("File Information", styles["Heading2"]))
    story.append(_table([
        ["Property", "Value"],
        ["Filename", metadata.get("name", "")],
        ["Size (KB)", str(metadata.get("size", ""))],
        ["Extension", metadata.get("extension", "")],
        ["MIME Type", str(metadata.get("mime", ""))],
    ]))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Hashes", styles["Heading2"]))
    story.append(_table([
        ["Type", "Value"],
        ["MD5", hashes.get("md5", "")],
        ["SHA1", hashes.get("sha1", "")],
        ["SHA256", hashes.get("sha256", "")],
    ], col_widths=[3 * cm, 12 * cm]))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Entropy", styles["Heading2"]))
    story.append(Paragraph(
        f"Overall file entropy: {entropy_info.get('entropy')} / 8.0 "
        f"({entropy_info.get('verdict')})",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.5 * cm))

    if not pe_info.get("error"):
        story.append(Paragraph("PE Analysis", styles["Heading2"]))
        story.append(_table([
            ["Property", "Value"],
            ["Architecture", pe_info.get("architecture", "")],
            ["Compile Time", pe_info.get("compile_time", "")],
            ["Entry Point", pe_info.get("entry_point", "")],
            ["Image Base", pe_info.get("image_base", "")],
            ["Number of Sections", str(pe_info.get("number_of_sections", ""))],
        ]))
        story.append(Spacer(1, 0.5 * cm))

    if yara_info.get("matches"):
        story.append(Paragraph("YARA Matches", styles["Heading2"]))
        rows = [["Rule", "Severity", "Description"]]
        for m in yara_info["matches"]:
            rows.append([m["rule"], m["severity"], m["description"]])
        story.append(_table(rows, col_widths=[5 * cm, 3 * cm, 7 * cm]))
        story.append(Spacer(1, 0.5 * cm))

    if strings_info.get("suspicious"):
        story.append(Paragraph("Suspicious Strings", styles["Heading2"]))
        rows = [["Category", "Value"]]
        for s in strings_info["suspicious"]:
            rows.append([s["category"], s["value"]])
        story.append(_table(rows, col_widths=[6 * cm, 9 * cm]))

    doc = SimpleDocTemplate(out_path, pagesize=A4)
    doc.build(story)

    return out_path
```

### analysis/history.py

```python
import os
from datetime import datetime, timezone

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

_client = None
_collection = None
_connection_error = None
_attempted = False


def _get_collection():
    """
    Lazily connect to MongoDB Atlas on first use (env vars are read here,
    not at import time, so this works correctly regardless of when
    load_dotenv() runs relative to this module being imported). Caches
    the connection (or the failure reason) for the lifetime of the
    process.
    """

    global _client, _collection, _connection_error, _attempted

    if _attempted:
        return _collection

    _attempted = True

    if not PYMONGO_AVAILABLE:
        _connection_error = "pymongo is not installed."
        return None

    mongodb_uri = os.environ.get("MONGODB_URI")
    mongodb_db = os.environ.get("MONGODB_DB", "mallnsight")

    if not mongodb_uri:
        _connection_error = "MONGODB_URI is not configured."
        return None

    try:
        _client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
        _client.admin.command("ping")
        _collection = _client[mongodb_db]["analyses"]
    except PyMongoError as e:
        _connection_error = str(e)
        return None

    return _collection


def _reset_cache():
    """Test-only hook to force the next call to reconnect from scratch."""

    global _client, _collection, _connection_error, _attempted
    _client = None
    _collection = None
    _connection_error = None
    _attempted = False


def is_available():
    _get_collection()
    return _connection_error is None


def get_connection_error():
    _get_collection()
    return _connection_error


def save_analysis(metadata, hashes, score_info):
    """
    Save a summary of one analysis run to MongoDB Atlas.
    Returns the inserted record's id as a string, or None if the
    database isn't configured/reachable (the caller should treat this
    as non-fatal).
    """

    collection = _get_collection()

    if collection is None:
        return None

    record = {
        "filename": metadata.get("name"),
        "size_kb": metadata.get("size"),
        "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"),
        "sha256": hashes.get("sha256"),
        "risk_score": score_info.get("score"),
        "verdict": score_info.get("verdict"),
        "reasons": score_info.get("reasons", []),
        "analyzed_at": datetime.now(timezone.utc),
    }

    try:
        result = collection.insert_one(record)
        return str(result.inserted_id)
    except PyMongoError:
        return None


def get_recent_analyses(limit=50):
    """
    Return the most recent analysis records, newest first.
    Returns an empty list if the database isn't configured/reachable.
    """

    collection = _get_collection()

    if collection is None:
        return []

    try:
        cursor = collection.find().sort("analyzed_at", -1).limit(limit)
        records = []

        for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            records.append(doc)

        return records
    except PyMongoError:
        return []
```

---

## YARA Rules

### yara_rules/suspicious_indicators.yar

```yara
import "math"

rule Suspicious_Process_Injection
{
    meta:
        description = "References APIs commonly used for process injection"
        severity = "HIGH"

    strings:
        $a1 = "CreateRemoteThread" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "VirtualAllocEx" ascii wide
        $a4 = "NtUnmapViewOfSection" ascii wide
        $a5 = "QueueUserAPC" ascii wide

    condition:
        2 of ($a*)
}

rule Suspicious_Dynamic_API_Resolution
{
    meta:
        description = "Resolves APIs dynamically, often used to evade static detection"
        severity = "MEDIUM"

    strings:
        $a1 = "LoadLibraryA" ascii wide
        $a2 = "LoadLibraryW" ascii wide
        $a3 = "GetProcAddress" ascii wide

    condition:
        all of them
}

rule Suspicious_Command_Execution
{
    meta:
        description = "Contains references to command interpreters / script hosts"
        severity = "MEDIUM"

    strings:
        $a1 = "cmd.exe" ascii wide nocase
        $a2 = "powershell.exe" ascii wide nocase
        $a3 = "wscript.exe" ascii wide nocase
        $a4 = "mshta.exe" ascii wide nocase
        $a5 = "WinExec" ascii

    condition:
        any of them
}

rule Suspicious_AntiDebug_AntiVM
{
    meta:
        description = "Contains anti-debugging or anti-VM checks"
        severity = "MEDIUM"

    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "VMware" ascii nocase
        $a4 = "VBox" ascii nocase
        $a5 = "Sandboxie" ascii nocase

    condition:
        any of them
}

rule Packed_File_High_Entropy
{
    meta:
        description = "Overall file entropy is very high, indicative of packing/encryption"
        severity = "MEDIUM"

    condition:
        filesize > 256 and math.entropy(0, filesize) >= 7.5
}
```

---

## Templates

### templates/base.html

```html
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>{% block title %}MallnSight{% endblock %}</title>

    <!-- Google Font -->

    <link rel="preconnect"
          href="https://fonts.googleapis.com">

    <link rel="preconnect"
          href="https://fonts.gstatic.com"
          crossorigin>

    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
          rel="stylesheet">

    <!-- Bootstrap -->

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet">

    <!-- Bootstrap Icons -->

    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">

    <!-- Tabler Icons -->

    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">

    <!-- CSS -->

    <link rel="stylesheet"
          href="{{ url_for('static', filename='css/style.css') }}">

</head>

<body>

<!-- NAVBAR -->

<nav class="navbar navbar-expand-lg navbar-dark fixed-top">

<div class="container">

<a class="navbar-brand"
   href="/">

<span class="logo-icon">

<i class="ti ti-shield-lock"></i>

</span>

MallnSight

</a>

<button class="navbar-toggler"
        type="button"
        data-bs-toggle="collapse"
        data-bs-target="#navbar">

<span class="navbar-toggler-icon"></span>

</button>

<div class="collapse navbar-collapse"
     id="navbar">

<ul class="navbar-nav ms-auto align-items-center">

<li class="nav-item">

<a class="nav-link {{ 'active' if request.path == '/' }}"
   href="/">

Home

</a>

</li>

<li class="nav-item">

<a class="nav-link {{ 'active' if request.path == '/features' }}"
   href="/features">

Features

</a>

</li>

<li class="nav-item">

<a class="nav-link {{ 'active' if request.path == '/about' }}"
   href="/about">

Documentation

</a>

</li>

<li class="nav-item">

<a class="nav-link {{ 'active' if request.path == '/history' }}"
   href="/history">

History

</a>

</li>

<li class="nav-item">

<a class="nav-link {{ 'active' if request.path == '/contact' }}"
   href="/contact">

Contact

</a>

</li>

<li class="nav-item">

<a class="nav-link"
   href="https://github.com/vibushasatheeshkumar/mallnsight"
   target="_blank" rel="noopener">

GitHub

</a>

</li>

<li class="nav-item ms-3">

<a class="btn btn-danger"

href="/upload">

Analyze File

</a>

</li>

</ul>

</div>

</div>

</nav>

<!-- PAGE -->

<main>

{% block content %}

{% endblock %}

</main>

<!-- FOOTER -->

<footer>

<div class="container">

<div class="row">

<div class="col-lg-6">

<h5>

MallnSight

</h5>

<p>

Static Malware Analysis &
Threat Intelligence Platform.

</p>

<p class="footer-small">

A VivarX Project

</p>

</div>

<div class="col-lg-3">

<h6>

Platform

</h6>

<a href="/features">

Features

</a>

<br>

<a href="/upload">

Analyze

</a>

</div>

<div class="col-lg-3">

<h6>

Resources

</h6>

<a href="/contact">

Contact

</a>

<br>

<a href="https://github.com/vibushasatheeshkumar/mallnsight" target="_blank" rel="noopener">

GitHub

</a>

<br>

<a href="https://www.linkedin.com/in/vibushasatheeshkumar" target="_blank" rel="noopener">

LinkedIn

</a>

</div>

</div>

<hr>

<div class="footer-bottom">

© 2026 MallnSight · A VivarX Project

</div>

</div>

</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

<script src="{{ url_for('static',filename='js/main.js') }}"></script>

</body>

</html>
```

### templates/home.html

```html
{% extends "base.html" %}

{% block title %}
MallnSight
{% endblock %}

{% block content %}

<!-- =====================================
HERO
===================================== -->

<section class="hero">

<div class="container">

<div class="row align-items-center">

<div class="col-lg-6">

<div class="project-badge">

<span>A</span>

<span class="project-name">

VivarX Project

</span>

</div>

<h1>

MallnSight

</h1>

<h2>

Static Malware Analysis &
<br>
Threat Intelligence Platform

</h2>

<p>

Analyze suspicious files safely without executing them.
Perform enterprise-grade static malware analysis using
hashing, PE parsing, entropy calculation, YARA detection,
and automated investigation reports.

</p>

<div class="feature-grid">

<div class="feature-item">

<i class="ti ti-fingerprint"></i>

<div>

<h6>Hash Analysis</h6>

<span>MD5 • SHA1 • SHA256</span>

</div>

</div>

<div class="feature-item">

<i class="ti ti-file-code"></i>

<div>

<h6>PE Analysis</h6>

<span>Headers • Imports</span>

</div>

</div>

<div class="feature-item">

<i class="ti ti-shield-search"></i>

<div>

<h6>YARA Rules</h6>

<span>Threat Detection</span>

</div>

</div>

<div class="feature-item">

<i class="ti ti-chart-histogram"></i>

<div>

<h6>Entropy</h6>

<span>Packed Detection</span>

</div>

</div>

</div>

<div class="hero-buttons">

<a href="/upload"
class="btn btn-danger btn-lg">

Start Investigation

</a>

<a href="/features"
class="btn btn-outline-light btn-lg">

Learn More

</a>

</div>

</div>

<div class="col-lg-6">

<div class="hero-image">

<i class="ti ti-shield-lock-filled"></i>

</div>

</div>

</div>

</div>

</section>

<!-- =====================================
FEATURES
===================================== -->

<section class="features-section">

<div class="container">

<div class="section-title">

<div class="section-tag">

PLATFORM CAPABILITIES

</div>

<h2>

Enterprise Static Analysis

</h2>

<p>

Everything required to investigate suspicious files
without executing them.

</p>

</div>

<div class="row g-4">

<div class="col-lg-4">

<div class="feature-card">

<i class="ti ti-fingerprint"></i>

<h4>

Hash Analysis

</h4>

<p>

Generate MD5, SHA1 and SHA256 hashes
for file fingerprinting.

</p>

</div>

</div>

<div class="col-lg-4">

<div class="feature-card">

<i class="ti ti-file-code"></i>

<h4>

PE Analysis

</h4>

<p>

Inspect executable headers, imports,
sections and entry points.

</p>

</div>

</div>

<div class="col-lg-4">

<div class="feature-card">

<i class="ti ti-shield-search"></i>

<h4>

YARA Detection

</h4>

<p>

Detect malware families using
enterprise-grade YARA signatures.

</p>

</div>

</div>

<div class="col-lg-4">

<div class="feature-card">

<i class="ti ti-chart-histogram"></i>

<h4>

Entropy Analysis

</h4>

<p>

Detect packed and obfuscated
executables through entropy.

</p>

</div>

</div>

<div class="col-lg-4">

<div class="feature-card">

<i class="ti ti-search"></i>

<h4>

String Extraction

</h4>

<p>

Extract URLs, registry keys,
commands and suspicious strings.

</p>

</div>

</div>

<div class="col-lg-4">

<div class="feature-card">

<i class="ti ti-file-description"></i>

<h4>

Investigation Report

</h4>

<p>

Generate a professional PDF report
with indicators and risk score.

</p>

</div>

</div>

</div>

</div>

</section>

<!-- =====================================
WORKFLOW
===================================== -->

<section class="workflow">

<div class="container">

<div class="section-title">

<div class="section-tag">

WORKFLOW

</div>

<h2>

How MallnSight Works

</h2>

<p>

Simple, safe and completely offline.

</p>

</div>

<div class="row g-4">

<div class="col-lg-3">

<div class="workflow-step">

<div class="workflow-number">

1

</div>

<h5>

Upload File

</h5>

<p>

Choose a suspicious executable
or document.

</p>

</div>

</div>

<div class="col-lg-3">

<div class="workflow-step">

<div class="workflow-number">

2

</div>

<h5>

Static Analysis

</h5>

<p>

Hashes, metadata,
PE analysis and strings.

</p>

</div>

</div>

<div class="col-lg-3">

<div class="workflow-step">

<div class="workflow-number">

3

</div>

<h5>

YARA Scan

</h5>

<p>

Detect known malware
families using rules.

</p>

</div>

</div>

<div class="col-lg-3">

<div class="workflow-step">

<div class="workflow-number">

4

</div>

<h5>

Investigation Report

</h5>

<p>

Download a detailed PDF
analysis report.

</p>

</div>

</div>

</div>

</div>

</section>

<!-- =====================================
CTA
===================================== -->

<section>

<div class="container">

<div class="cta">

<h2>

Ready to Investigate?

</h2>

<p>

Start analyzing suspicious files safely
using MallnSight.

</p>

<a href="/upload"
class="btn btn-danger btn-lg">

Analyze File

</a>

</div>

</div>

</section>

{% endblock %}
```

### templates/features.html

```html
{% extends "base.html" %}

{% block title %}Features | MallnSight{% endblock %}

{% block content %}

<section class="page-hero">
<div class="container text-center">

<div class="section-tag">PLATFORM CAPABILITIES</div>

<h1 class="mt-3">Everything You Need for Static Analysis</h1>

<p class="text-secondary mt-3 mx-auto" style="max-width:720px;">
MallnSight inspects suspicious files completely offline &mdash; no code is
ever executed. Every capability below runs locally in your own environment.
</p>

</div>
</section>

<section class="features-section pt-0">
<div class="container">

<div class="row g-4">

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-fingerprint"></i>
<h4>Hash Analysis</h4>
<p>
Generates MD5, SHA1 and SHA256 hashes for unique file fingerprinting,
useful for threat-intel lookups and de-duplication.
</p>
</div>
</div>

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-file-info"></i>
<h4>File Metadata</h4>
<p>
Extracts filename, size, extension and MIME type to quickly
characterize an unknown sample.
</p>
</div>
</div>

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-file-code"></i>
<h4>PE Analysis</h4>
<p>
Parses Windows PE headers &mdash; architecture, compile timestamp,
entry point, image base, sections, imports and exports &mdash;
via <code>pefile</code>.
</p>
</div>
</div>

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-chart-histogram"></i>
<h4>Entropy Analysis</h4>
<p>
Calculates whole-file and per-section Shannon entropy to flag
packed, encrypted or obfuscated binaries.
</p>
</div>
</div>

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-search"></i>
<h4>String Extraction</h4>
<p>
Pulls ASCII and UTF-16LE strings and automatically flags suspicious
indicators &mdash; injection APIs, command interpreters, registry
persistence, URLs, IPs and anti-debug checks.
</p>
</div>
</div>

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-shield-search"></i>
<h4>YARA Detection</h4>
<p>
Scans against a bundled, extensible YARA rule set covering process
injection, dynamic API resolution, command execution and packing.
</p>
</div>
</div>

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-gauge"></i>
<h4>Risk Scoring</h4>
<p>
Combines every signal above into a single 0&ndash;100 risk score and
a clear verdict: Clean, Low Risk, Suspicious or High Risk.
</p>
</div>
</div>

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-file-description"></i>
<h4>PDF Investigation Report</h4>
<p>
One-click export of the full findings into a shareable PDF report,
generated with <code>reportlab</code>.
</p>
</div>
</div>

<div class="col-lg-4 col-md-6">
<div class="feature-card">
<i class="ti ti-lock"></i>
<h4>Fully Offline</h4>
<p>
Nothing is uploaded to a third party. Files, hashes and results stay
on the machine running MallnSight.
</p>
</div>
</div>

</div>

</div>
</section>

<section>
<div class="container">
<div class="cta">
<h2>See It In Action</h2>
<p>Upload a file and get a full static analysis report in seconds.</p>
<a href="/upload" class="btn btn-danger btn-lg">Analyze File</a>
</div>
</div>
</section>

{% endblock %}
```

### templates/about.html

```html
{% extends "base.html" %}

{% block title %}Documentation | MallnSight{% endblock %}

{% block content %}

<section class="page-hero">
<div class="container text-center">

<div class="section-tag">DOCUMENTATION</div>

<h1 class="mt-3">MallnSight Documentation</h1>

<p class="text-secondary mt-3 mx-auto" style="max-width:720px;">
A complete reference for what MallnSight does, how it's built, and how
to run it yourself.
</p>

<a href="https://github.com/vibushasatheeshkumar/mallnsight"
   target="_blank" rel="noopener"
   class="btn btn-outline-light mt-4">
    <i class="ti ti-brand-github"></i>
    View Source on GitHub
</a>

</div>
</section>

<section class="docs-section">
<div class="container">

<div class="row g-5">

<!-- TOC -->
<div class="col-lg-3">
<nav class="doc-toc">
<h6>On this page</h6>
<a href="#overview">Overview</a>
<a href="#tech-stack">Tech Stack</a>
<a href="#structure">Project Structure</a>
<a href="#getting-started">Getting Started</a>
<a href="#usage">Usage</a>
<a href="#yara">Extending YARA Rules</a>
<a href="#deployment">Deployment</a>
<a href="#disclaimer">Disclaimer</a>
</nav>
</div>

<!-- CONTENT -->
<div class="col-lg-9">

<div class="doc-block" id="overview">
<h3>Overview</h3>
<p>
MallnSight is a Flask-based web application for performing
<strong>offline, static analysis</strong> of suspicious files. It never
executes the uploaded file &mdash; it inspects hashes, PE structure,
entropy, embedded strings and YARA signatures to produce a risk score
and a downloadable PDF investigation report.
</p>
<p>All analysis runs locally; no file or hash is ever sent to a third-party service.</p>
</div>

<div class="doc-block" id="tech-stack">
<h3>Tech Stack</h3>
<ul class="doc-list">
<li><strong>Backend:</strong> Python, Flask</li>
<li><strong>PE Parsing:</strong> pefile</li>
<li><strong>Pattern Matching:</strong> yara-python</li>
<li><strong>PDF Generation:</strong> reportlab</li>
<li><strong>Frontend:</strong> Jinja2, Bootstrap 5, vanilla JS</li>
<li><strong>CI:</strong> GitHub Actions (pytest on Python 3.11 / 3.12)</li>
</ul>
</div>

<div class="doc-block" id="structure">
<h3>Project Structure</h3>
<pre class="doc-code"><code>mallnsight/
├── app.py                  # Flask routes & request handling
├── analysis/
│   ├── hash.py              # MD5 / SHA1 / SHA256
│   ├── metadata.py           # File info (size, MIME, extension)
│   ├── pe_analysis.py        # PE header / sections / imports / exports
│   ├── entropy.py            # Shannon entropy
│   ├── strings.py            # String extraction + suspicious indicators
│   ├── yara_scan.py          # YARA rule compilation & scanning
│   ├── scoring.py            # Risk score & verdict
│   └── report.py             # PDF report generation
├── yara_rules/                # Bundled .yar rule files
├── templates/                  # Jinja2 pages
├── static/                     # CSS / JS / assets
├── tests/                        # pytest smoke tests
├── uploads/                       # Uploaded files (runtime only)
└── reports/                        # Generated PDF reports (runtime only)</code></pre>
</div>

<div class="doc-block" id="getting-started">
<h3>Getting Started</h3>

<h5>Prerequisites</h5>
<ul class="doc-list">
<li>Python 3.11 or 3.12 (prebuilt <code>yara-python</code> wheels are available for these versions)</li>
<li>On Windows, building <code>yara-python</code> from source requires the
<a href="https://visualstudio.microsoft.com/visual-cpp-build-tools/" target="_blank" rel="noopener">Microsoft C++ Build Tools</a></li>
</ul>

<h5>Setup</h5>
<pre class="doc-code"><code>git clone git@github.com:vibushasatheeshkumar/mallnsight.git
cd mallnsight

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt</code></pre>

<h5>Run</h5>
<pre class="doc-code"><code>python app.py</code></pre>
<p>The app starts at <code>http://127.0.0.1:5000</code>. Debug mode is off by default; set <code>FLASK_DEBUG=1</code> to enable it during development.</p>
</div>

<div class="doc-block" id="usage">
<h3>Usage</h3>
<ol class="doc-list">
<li>Go to <code>/upload</code>.</li>
<li>Drag and drop, or browse, a file to analyze (<code>.exe</code>, <code>.dll</code>, <code>.sys</code>, <code>.msi</code>, <code>.zip</code>, <code>.apk</code>, <code>.pdf</code>, <code>.docx</code>, <code>.bin</code>).</li>
<li>View the generated investigation dashboard: risk score, hashes, PE breakdown, entropy chart, suspicious strings, and YARA matches.</li>
<li>Download the findings as a PDF report.</li>
</ol>
<p>Uploaded files are size-limited to 100&nbsp;MB and stored under a randomly generated filename to avoid collisions.</p>
</div>

<div class="doc-block" id="yara">
<h3>Extending YARA Rules</h3>
<p>
Drop additional <code>.yar</code> files into <code>yara_rules/</code> &mdash;
they're compiled and scanned automatically on the next analysis request.
Each rule should set a <code>severity</code> meta field
(<code>HIGH</code>, <code>MEDIUM</code>, or <code>LOW</code>), which feeds
directly into the risk score.
</p>
</div>

<div class="doc-block" id="deployment">
<h3>Deployment</h3>
<p>
MallnSight ships ready to deploy on <a href="https://render.com" target="_blank" rel="noopener">Render</a>'s free tier:
</p>
<ul class="doc-list">
<li>The repo includes a <code>Procfile</code> (<code>waitress-serve --host=0.0.0.0 --port=$PORT app:app</code>) and a <code>runtime.txt</code> pinning Python 3.12.</li>
<li>On Render: New &rarr; Web Service &rarr; connect this GitHub repo &rarr; Build Command <code>pip install -r requirements.txt</code> &rarr; Start Command is picked up automatically from the <code>Procfile</code>.</li>
<li>The free tier's filesystem is ephemeral &mdash; uploaded files and generated reports won't persist across restarts, which is expected for a stateless demo deployment.</li>
</ul>
</div>

<div class="doc-block" id="disclaimer">
<h3>Disclaimer</h3>
<p>
MallnSight performs <strong>static</strong> analysis only &mdash; it does
not execute or detonate uploaded files. It is intended for educational and
authorized security research/testing purposes. Always handle suspicious
files in accordance with your organization's security policy.
</p>
</div>

</div>

</div>

</div>
</section>

{% endblock %}
```

### templates/upload.html

```html
{% extends "base.html" %}

{% block title %}Analyze File | MallnSight{% endblock %}

{% block content %}

<section class="upload-page">

<div class="container">

    <!-- Header -->

    <div class="row justify-content-center">

        <div class="col-lg-8 text-center">

            <span class="section-tag">
                OFFLINE STATIC ANALYSIS
            </span>

            <h1 class="display-4 fw-bold mt-3">

                Analyze Suspicious Files

            </h1>

            <p class="text-secondary mt-4">

                Upload suspicious files for enterprise-grade malware analysis.
                MallnSight performs completely offline static inspection using
                hashing, PE analysis, string extraction, entropy analysis and
                YARA detection.

            </p>

        </div>

    </div>

    <!-- Upload Card -->

    <div class="row justify-content-center mt-5">

        <div class="col-lg-9">

            <form
                action="/analyze"
                method="POST"
                enctype="multipart/form-data">

                <div class="upload-card">

                    <div class="upload-icon">

                        <i class="ti ti-cloud-upload"></i>

                    </div>

                    <h2>

                        Drag & Drop Your File

                    </h2>

                    <p class="text-secondary mt-3">

                        or browse a file from your computer

                    </p>

                    <input
                        type="file"
                        id="fileInput"
                        name="file"
                        hidden>

                    <label
                        for="fileInput"
                        class="browse-btn mt-4">

                        <i class="ti ti-folder-open"></i>

                        Browse File

                    </label>

                    <div
                        id="filename"
                        class="selected-file mt-4">

                        No file selected

                    </div>

                    <div class="supported-files mt-5">

                        <h6>

                            Supported Formats

                        </h6>

                        <div class="mt-3">

                            <span class="file-pill">EXE</span>

                            <span class="file-pill">DLL</span>

                            <span class="file-pill">MSI</span>

                            <span class="file-pill">ZIP</span>

                            <span class="file-pill">APK</span>

                            <span class="file-pill">PDF</span>

                            <span class="file-pill">DOCX</span>

                        </div>

                    </div>

                    <button
                        type="submit"
                        class="analyze-btn mt-5">

                        <i class="ti ti-shield-search"></i>

                        Start Investigation

                    </button>

                </div>

            </form>

        </div>

    </div>

</div>

</section>

<script>

const fileInput=document.getElementById("fileInput");

const filename=document.getElementById("filename");

fileInput.addEventListener("change",()=>{

    if(fileInput.files.length>0){

        filename.innerHTML=fileInput.files[0].name;

    }

});

</script>

{% endblock %}
/* =====================================================
                UPLOAD PAGE
===================================================== */

.upload-page{

    padding-top:140px;
    padding-bottom:120px;

}

/* Upload Card */

.upload-card{

    background:#161B22;
    border:1px solid #30363D;
    border-radius:20px;

    padding:70px 50px;

    text-align:center;

    transition:.35s;

}

.upload-card:hover{

    border-color:#E11D48;

    transform:translateY(-5px);

    box-shadow:0 20px 45px rgba(225,29,72,.12);

}

/* Upload Icon */

.upload-icon{

    width:110px;
    height:110px;

    margin:auto;

    border-radius:50%;

    display:flex;
    align-items:center;
    justify-content:center;

    background:#1C2128;

    color:#E11D48;

    font-size:50px;

    margin-bottom:30px;

    animation:uploadPulse 3s ease-in-out infinite;

}

@keyframes uploadPulse{

    0%,100%{

        transform:scale(1);

        box-shadow:0 0 0 rgba(225,29,72,0);

    }

    50%{

        transform:scale(1.08);

        box-shadow:0 0 25px rgba(225,29,72,.35);

    }

}

/* Browse Button */

.browse-btn{

    display:inline-flex;

    align-items:center;

    gap:10px;

    padding:14px 30px;

    border-radius:10px;

    background:#E11D48;

    color:white;

    font-weight:600;

    cursor:pointer;

    transition:.3s;

    text-decoration:none;

}

.browse-btn:hover{

    background:#F43F5E;

    transform:translateY(-3px);

    color:white;

}

/* Selected File */

.selected-file{

    color:#CBD5E1;

    font-weight:600;

}

/* Supported Files */

.supported-files h6{

    color:#9AA3B2;

    font-size:14px;

    letter-spacing:1px;

}

.file-pill{

    display:inline-block;

    margin:6px;

    padding:8px 16px;

    background:#1C2128;

    border:1px solid #30363D;

    border-radius:30px;

    color:#CBD5E1;

    transition:.3s;

}

.file-pill:hover{

    border-color:#E11D48;

    transform:translateY(-2px);

}

/* Analyze Button */

.analyze-btn{

    border:none;

    background:#E11D48;

    color:white;

    border-radius:10px;

    padding:15px 38px;

    display:inline-flex;

    align-items:center;

    justify-content:center;

    gap:12px;

    font-size:16px;

    font-weight:600;

    transition:.35s;

    position:relative;

    overflow:hidden;

}

.analyze-btn::before{

    content:"";

    position:absolute;

    top:0;

    left:-120%;

    width:40%;

    height:100%;

    background:linear-gradient(

        90deg,

        transparent,

        rgba(255,255,255,.45),

        transparent

    );

    transform:skewX(-20deg);

    animation:scanButton 3s linear infinite;

}

@keyframes scanButton{

    100%{

        left:150%;

    }

}

.analyze-btn:hover{

    background:#F43F5E;

    transform:translateY(-3px);

    box-shadow:0 15px 35px rgba(225,29,72,.30);

}

/* Responsive */

@media(max-width:768px){

.upload-card{

    padding:40px 25px;

}

.upload-icon{

    width:80px;

    height:80px;

    font-size:36px;

}

.analyze-btn{

    width:100%;

}

.browse-btn{

    width:100%;

    justify-content:center;

}

}
/* ==========================================
   SECURITY SECTION
========================================== */

.security-section{

    margin-top:90px;

}

.security-card{

    background:#161B22;

    border:1px solid #30363D;

    border-radius:18px;

    padding:35px;

    text-align:center;

    height:100%;

    transition:.35s ease;

}

.security-card:hover{

    transform:translateY(-8px);

    border-color:#E11D48;

    box-shadow:0 18px 40px rgba(225,29,72,.12);

}

.security-icon{

    width:70px;

    height:70px;

    margin:auto;

    margin-bottom:22px;

    border-radius:50%;

    background:#1C2128;

    display:flex;

    align-items:center;

    justify-content:center;

    transition:.35s;

}

.security-card:hover .security-icon{

    background:#E11D48;

}

.security-icon i{

    font-size:30px;

    color:#E11D48;

    transition:.35s;

}

.security-card:hover .security-icon i{

    color:white;

}

.security-card h4{

    font-size:22px;

    font-weight:700;

    margin-bottom:15px;

}

.security-card p{

    color:#9AA3B2;

    line-height:1.8;

}

/* ==========================================
   WHY MALLNSIGHT
========================================== */

.investigation-info{

    margin-top:70px;

    background:#161B22;

    border:1px solid #30363D;

    border-radius:22px;

    padding:60px;

    text-align:center;

}

.investigation-info h3{

    font-size:34px;

    font-weight:700;

    margin-bottom:18px;

}

.investigation-info p{

    max-width:760px;

    margin:auto;

    color:#9AA3B2;

    line-height:1.9;

}

.info-tags{

    margin-top:35px;

}

.info-tags span{

    display:inline-block;

    margin:6px;

    padding:10px 18px;

    border-radius:30px;

    border:1px solid #30363D;

    background:#1C2128;

    color:#CBD5E1;

    transition:.3s;

}

.info-tags span:hover{

    border-color:#E11D48;

    color:white;

    transform:translateY(-2px);

}

/* ==========================================
   DRAG & DROP EFFECT
========================================== */

.upload-card.dragover{

    border:2px dashed #E11D48;

    background:#1A1F28;

    transform:scale(1.02);

    box-shadow:0 0 35px rgba(225,29,72,.25);

}

/* ==========================================
   FILE NAME
========================================== */

.selected-file{

    display:inline-block;

    margin-top:25px;

    padding:10px 18px;

    border-radius:30px;

    background:#1C2128;

    border:1px solid #30363D;

    color:#CBD5E1;

}

/* ==========================================
   SMOOTH ANIMATION
========================================== */

.upload-card,
.security-card,
.investigation-info{

    animation:fadeUp .8s ease;

}

@keyframes fadeUp{

    from{

        opacity:0;

        transform:translateY(30px);

    }

    to{

        opacity:1;

        transform:translateY(0);

    }

}
```

### templates/dashboard.html

```html
{% extends "base.html" %}

{% block title %}Investigation Report | MallnSight{% endblock %}

{% block content %}

<section class="dashboard-page">
<div class="container">

{% if not metadata %}

<div class="error-box">
    No analysis results yet. <a href="/upload">Upload a file</a> to get started.
</div>

{% else %}

{% set risk_class = {
    "HIGH RISK": "risk-high",
    "SUSPICIOUS": "risk-medium",
    "LOW RISK": "risk-low",
    "CLEAN": "risk-clean"
}.get(score_info.verdict, "risk-low") %}

<!-- ===========================
VERDICT
=========================== -->

<div class="verdict-card">
<div class="row align-items-center">

<div class="col-lg-8">

<span class="verdict-tag {{ risk_class }}">
{{ score_info.verdict }}
</span>

<h2 class="mt-3">
{{ metadata.name }}
</h2>

<p>
This file was analyzed offline using hashing, PE inspection, entropy
analysis, string extraction and YARA pattern matching.
</p>

{% if score_info.reasons %}
<ul class="text-secondary">
    {% for reason in score_info.reasons %}
    <li>{{ reason }}</li>
    {% endfor %}
</ul>
{% endif %}

</div>

<div class="col-lg-4 text-end">

<div class="risk-circle {{ risk_class }}">
{{ score_info.score }}%
</div>

<span class="risk-label">
Risk Score
</span>

</div>

</div>
</div>

<!-- ===========================
FILE INFO
=========================== -->

<div class="row mt-5 g-4">

<div class="col-lg-6">
<div class="report-card">
<h4>File Information</h4>
<table class="table table-dark">
<tr><td>Filename</td><td>{{ metadata.name }}</td></tr>
<tr><td>File Size</td><td>{{ metadata.size }} KB</td></tr>
<tr><td>Extension</td><td>{{ metadata.extension }}</td></tr>
<tr><td>MIME</td><td>{{ metadata.mime or "Unknown" }}</td></tr>
</table>
</div>
</div>

<div class="col-lg-6">
<div class="report-card">
<h4>Hashes</h4>
<table class="table table-dark">
<tr>
<td>MD5</td>
<td>
<span class="hash-value">{{ hashes.md5 }}</span>
<button class="copy-btn" data-copy="{{ hashes.md5 }}">Copy</button>
</td>
</tr>
<tr>
<td>SHA1</td>
<td>
<span class="hash-value">{{ hashes.sha1 }}</span>
<button class="copy-btn" data-copy="{{ hashes.sha1 }}">Copy</button>
</td>
</tr>
<tr>
<td>SHA256</td>
<td>
<span class="hash-value">{{ hashes.sha256 }}</span>
<button class="copy-btn" data-copy="{{ hashes.sha256 }}">Copy</button>
</td>
</tr>
</table>
</div>
</div>

</div>

<!-- ===========================
PE ANALYSIS
=========================== -->

<div class="row mt-4">
<div class="col-lg-12">
<div class="report-card">
<h4>PE Analysis</h4>

{% if pe_info.error %}

<div class="error-box">
    Not a recognized PE file ({{ pe_info.error }}). PE-specific analysis
    (imports, exports, sections) is unavailable for this file type.
</div>

{% else %}

<table class="table table-dark">
<thead>
<tr><th>Property</th><th>Value</th></tr>
</thead>
<tbody>
<tr><td>Architecture</td><td>{{ pe_info.architecture }}</td></tr>
<tr><td>Compile Time</td><td>{{ pe_info.compile_time }}</td></tr>
<tr><td>Entry Point</td><td>{{ pe_info.entry_point }}</td></tr>
<tr><td>Image Base</td><td>{{ pe_info.image_base }}</td></tr>
<tr><td>Number of Sections</td><td>{{ pe_info.number_of_sections }}</td></tr>
</tbody>
</table>

<h5 class="mt-4">Sections</h5>
<table class="table table-dark">
<thead>
<tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th></tr>
</thead>
<tbody>
{% for section in pe_info.sections %}
<tr>
<td>{{ section.name }}</td>
<td>{{ section.virtual_size }}</td>
<td>{{ section.raw_size }}</td>
<td>{{ section.entropy }}</td>
</tr>
{% endfor %}
</tbody>
</table>

<h5 class="mt-4">Imports ({{ pe_info.imports|length }})</h5>
{% if pe_info.imports %}
<table class="table table-dark">
<thead>
<tr><th>DLL</th><th>Function</th></tr>
</thead>
<tbody>
{% for imp in pe_info.imports[:50] %}
<tr><td>{{ imp.dll }}</td><td>{{ imp.function }}</td></tr>
{% endfor %}
</tbody>
</table>
{% if pe_info.imports|length > 50 %}
<small class="text-secondary">Showing first 50 of {{ pe_info.imports|length }} imports.</small>
{% endif %}
{% else %}
<p class="text-secondary">No imports found.</p>
{% endif %}

<h5 class="mt-4">Exports ({{ pe_info.exports|length }})</h5>
{% if pe_info.exports %}
<ul>
{% for exp in pe_info.exports %}
<li>{{ exp }}</li>
{% endfor %}
</ul>
{% else %}
<p class="text-secondary">No exported functions found.</p>
{% endif %}

{% endif %}

</div>
</div>
</div>

<!-- ===========================
YARA
=========================== -->

<div class="row mt-4">

<div class="col-lg-6">
<div class="report-card">
<h4>YARA Matches</h4>

{% if not yara_info.available %}

<div class="error-box">
    YARA scanning unavailable: {{ yara_info.error }}
</div>

{% elif yara_info.matches %}

<table class="table table-dark">
<thead>
<tr><th>Rule</th><th>Severity</th></tr>
</thead>
<tbody>
{% for match in yara_info.matches %}
<tr>
<td>{{ match.rule }}</td>
<td>
{% if match.severity == "HIGH" %}
<span class="badge bg-danger">HIGH</span>
{% elif match.severity == "MEDIUM" %}
<span class="badge bg-warning text-dark">MEDIUM</span>
{% else %}
<span class="badge bg-secondary">LOW</span>
{% endif %}
</td>
</tr>
{% endfor %}
</tbody>
</table>

{% else %}

<p class="text-secondary">No YARA rules matched.</p>

{% endif %}

</div>
</div>

<!-- ===========================
ENTROPY
=========================== -->

<div class="col-lg-6">
<div class="report-card">
<h4>File Entropy</h4>

<div class="entropy-item">
<span>Overall ({{ entropy_info.verdict }})</span>
<div class="progress">
{% set pct = (entropy_info.entropy / 8 * 100)|round(1) %}
<div class="progress-bar {% if entropy_info.entropy >= 7.5 %}bg-danger{% elif entropy_info.entropy >= 6.5 %}bg-warning{% else %}bg-success{% endif %}" style="width:{{ pct }}%">
</div>
</div>
<small>{{ entropy_info.entropy }} / 8.0</small>
</div>

{% if not pe_info.error %}
{% for section in pe_info.sections %}
<div class="entropy-item mt-4">
<span>{{ section.name }}</span>
<div class="progress">
{% set spct = (section.entropy / 8 * 100)|round(1) %}
<div class="progress-bar {% if section.entropy >= 7.5 %}bg-danger{% elif section.entropy >= 6.5 %}bg-warning{% else %}bg-success{% endif %}" style="width:{{ spct }}%">
</div>
</div>
<small>{{ section.entropy }} / 8.0</small>
</div>
{% endfor %}
{% endif %}

</div>
</div>

</div>

<!-- ===========================
STRINGS
=========================== -->

<div class="row mt-4">
<div class="col-lg-12">
<div class="report-card">
<h4>Suspicious Strings ({{ strings_info.suspicious|length }})</h4>

{% if strings_info.suspicious %}

<div class="strings-box">
{% for s in strings_info.suspicious %}
<span class="string-pill" title="{{ s.category }}">{{ s.value }}</span>
{% endfor %}
</div>

{% else %}

<p class="text-secondary">No suspicious strings detected.</p>

{% endif %}

<p class="text-secondary mt-3">
{{ strings_info.total_strings }} printable strings extracted in total.
</p>

</div>
</div>
</div>

<!-- ===========================
DOWNLOAD
=========================== -->

<div class="text-center mt-5">
<a href="/download/{{ download_id }}" class="btn btn-danger btn-lg download-btn">
<i class="ti ti-download"></i>
Download PDF Report
</a>
</div>

{% endif %}

</div>
</section>

<script>
document.querySelectorAll(".copy-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        navigator.clipboard.writeText(btn.dataset.copy);
        const original = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = original; }, 1500);
    });
});
</script>

{% endblock %}
```

### templates/history.html

```html
{% extends "base.html" %}

{% block title %}History | MallnSight{% endblock %}

{% block content %}

<section class="page-hero">
<div class="container text-center">

<div class="section-tag">CLOUD ANALYSIS HISTORY</div>

<h1 class="mt-3">Recent Analyses</h1>

<p class="text-secondary mt-3 mx-auto" style="max-width:680px;">
Past results stored in MongoDB Atlas, so previously analyzed files stay
searchable even after the local upload/report files are gone.
</p>

</div>
</section>

<section class="pt-0">
<div class="container">

{% if not available %}

<div class="error-box">
    History is unavailable: {{ error }}.
    See <code>DEVELOPER_GUIDE.md</code> for how to configure
    <code>MONGODB_URI</code> to enable this feature.
</div>

{% elif not records %}

<div class="report-card text-center">
<p class="text-secondary mb-0">
No analyses recorded yet. Results are saved here automatically every
time a file is analyzed.
</p>
</div>

{% else %}

<div class="report-card">
<table class="table table-dark">
<thead>
<tr>
<th>Analyzed At (UTC)</th>
<th>Filename</th>
<th>SHA256</th>
<th>Verdict</th>
<th>Risk Score</th>
</tr>
</thead>
<tbody>
{% for record in records %}
<tr>
<td>{{ record.analyzed_at.strftime("%Y-%m-%d %H:%M") if record.analyzed_at else "—" }}</td>
<td>{{ record.filename }}</td>
<td><span class="hash-value">{{ record.sha256[:16] }}&hellip;</span></td>
<td>
{% if record.verdict == "HIGH RISK" %}
<span class="badge bg-danger">{{ record.verdict }}</span>
{% elif record.verdict == "SUSPICIOUS" %}
<span class="badge bg-warning text-dark">{{ record.verdict }}</span>
{% elif record.verdict == "LOW RISK" %}
<span class="badge bg-primary">{{ record.verdict }}</span>
{% else %}
<span class="badge bg-success">{{ record.verdict }}</span>
{% endif %}
</td>
<td>{{ record.risk_score }}/100</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>

{% endif %}

</div>
</section>

{% endblock %}
```

### templates/contact.html

```html
{% extends "base.html" %}

{% block title %}Contact | MallnSight{% endblock %}

{% block content %}

<section class="page-hero">
<div class="container text-center">

<div class="section-tag">GET IN TOUCH</div>

<h1 class="mt-3">Contact</h1>

<p class="text-secondary mt-3 mx-auto" style="max-width:620px;">
Questions, bug reports, or ideas for MallnSight? Reach out directly
or open an issue on GitHub.
</p>

</div>
</section>

<section class="pt-0">
<div class="container">

<div class="row g-4 justify-content-center">

<div class="col-lg-4 col-md-6">
<a href="mailto:vibushasatheeshkumar@gmail.com" class="contact-card">
<i class="ti ti-mail"></i>
<h4>Email</h4>
<p>vibushasatheeshkumar@gmail.com</p>
</a>
</div>

<div class="col-lg-4 col-md-6">
<a href="https://github.com/vibushasatheeshkumar/mallnsight" target="_blank" rel="noopener" class="contact-card">
<i class="ti ti-brand-github"></i>
<h4>GitHub</h4>
<p>vibushasatheeshkumar/mallnsight</p>
</a>
</div>

<div class="col-lg-4 col-md-6">
<a href="https://www.linkedin.com/in/vibushasatheeshkumar" target="_blank" rel="noopener" class="contact-card">
<i class="ti ti-brand-linkedin"></i>
<h4>LinkedIn</h4>
<p>linkedin.com/in/vibushasatheeshkumar</p>
</a>
</div>

</div>

</div>
</section>

{% endblock %}
```

---

## Static Assets

### static/css/style.css

```css
/* ==========================================
   MALLNSIGHT ENTERPRISE UI
========================================== */

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

:root{

    --bg:#0D1117;
    --surface:#161B22;
    --card:#1C2128;
    --border:#30363D;

    --primary:#E11D48;
    --primary-hover:#F43F5E;

    --text:#F8FAFC;
    --muted:#9AA3B2;

    --success:#22C55E;
    --warning:#FACC15;
    --danger:#EF4444;

}

*{
    margin:0;
    padding:0;
    box-sizing:border-box;
}

html{

    scroll-behavior:smooth;

}

body{

    background:var(--bg);

    color:var(--text);

    font-family:"Inter",sans-serif;

    overflow-x:hidden;

    line-height:1.7;

}

/* ===============================
   BACKGROUND
================================ */

body::before{

    content:"";

    position:fixed;

    inset:0;

    background-image:

    linear-gradient(rgba(255,255,255,.02) 1px,transparent 1px),

    linear-gradient(90deg,rgba(255,255,255,.02) 1px,transparent 1px);

    background-size:60px 60px;

    opacity:.25;

    pointer-events:none;

    z-index:-2;

}

body::after{

    content:"";

    position:fixed;

    inset:0;

    background:

    radial-gradient(circle at 20% 20%,rgba(255,255,255,.02),transparent 35%),

    radial-gradient(circle at 80% 70%,rgba(255,255,255,.015),transparent 35%);

    z-index:-1;

    pointer-events:none;

}

/* ===============================
   NAVBAR
================================ */

.navbar{

    background:rgba(13,17,23,.92);

    backdrop-filter:blur(12px);

    border-bottom:1px solid var(--border);

    padding:14px 0;

}

.navbar-brand{

    color:white!important;

    font-weight:700;

    font-size:24px;

    letter-spacing:.3px;

}

.logo-icon{

    color:var(--primary);

    margin-right:10px;

}

.nav-link{

    color:var(--muted)!important;

    margin-left:18px;

    font-weight:500;

    transition:.3s;

}

.nav-link:hover{

    color:white!important;

}

.nav-link.active{

    color:white!important;

}

/* ===============================
   BUTTONS
================================ */

.btn{

    border-radius:8px!important;

    transition:.3s;

}

.btn-danger{

    background:var(--primary);

    border:none;

}

.btn-danger:hover{

    background:var(--primary-hover);

    transform:translateY(-2px);

    box-shadow:0 12px 25px rgba(225,29,72,.20);

}

.btn-outline-light:hover{

    transform:translateY(-2px);

}

/* ===============================
   HERO
================================ */

.hero{

    min-height:92vh;

    display:flex;

    align-items:center;

    padding-top:90px;

}

.hero h1{

    font-size:74px;

    font-weight:800;

    margin-bottom:15px;

}

.hero h2{

    color:#9AA3B2;

    font-weight:400;

    font-size:28px;

    line-height:1.5;

}

.hero p{

    color:#94A3B8;

    font-size:18px;

    margin-top:30px;

    max-width:620px;

}

.hero-buttons{

    display:flex;

    gap:15px;

    margin-top:40px;

}

.project-badge{

    display:inline-flex;

    align-items:center;

    gap:8px;

    background:#161B22;

    border:1px solid var(--border);

    color:#9AA3B2;

    border-radius:25px;

    padding:8px 18px;

    font-size:13px;

    margin-bottom:20px;

}

.project-name{

    color:var(--primary);

    font-weight:700;

}

/* ===============================
   RIGHT ILLUSTRATION
================================ */

.hero-image{

    display:flex;

    justify-content:flex-end;

    align-items:center;

}

.hero-image i{

    font-size:130px;

    color:var(--primary);

}

/* ===============================
   FEATURE GRID
================================ */

.feature-grid{

    display:grid;

    grid-template-columns:repeat(2,1fr);

    gap:18px;

    margin-top:35px;

}

.feature-item{

    background:#161B22;

    border:1px solid var(--border);

    border-radius:14px;

    padding:18px;

    display:flex;

    align-items:center;

    gap:16px;

    transition:.35s;

}

.feature-item:hover{

    border-color:var(--primary);

    transform:translateY(-5px);

}

.feature-item i{

    font-size:24px;

    color:var(--primary);

}

.feature-item h6{

    margin:0;

    font-weight:600;

}

.feature-item span{

    font-size:13px;

    color:#94A3B8;

}

/* ===============================
   SECTION
================================ */

section{

    padding:110px 0;

}

.section-title{

    text-align:center;

    margin-bottom:70px;

}

.section-tag{

    color:var(--primary);

    text-transform:uppercase;

    letter-spacing:2px;

    font-size:13px;

    font-weight:600;

}

.section-title h2{

    font-size:44px;

    font-weight:700;

    margin-top:15px;

}

.section-title p{

    color:#9AA3B2;

    max-width:650px;

    margin:auto;

    margin-top:18px;

}

/* ==========================================
   FEATURE CARDS
========================================== */

.features-section{

    padding-top:40px;

}

.feature-card{

    background:var(--surface);

    border:1px solid var(--border);

    border-radius:18px;

    padding:35px;

    height:100%;

    transition:.35s ease;

}

.feature-card:hover{

    transform:translateY(-8px);

    border-color:var(--primary);

    box-shadow:0 18px 40px rgba(225,29,72,.10);

}

.feature-card i{

    font-size:38px;

    color:var(--primary);

    margin-bottom:25px;

}

.feature-card h4{

    font-size:22px;

    font-weight:700;

    margin-bottom:15px;

}

.feature-card p{

    color:var(--muted);

    font-size:15px;

    line-height:1.8;

}

/* ==========================================
   WORKFLOW
========================================== */

.workflow{

    position:relative;

}

.workflow-step{

    background:var(--surface);

    border:1px solid var(--border);

    border-radius:16px;

    padding:30px;

    text-align:center;

    position:relative;

    transition:.3s;

}

.workflow-step:hover{

    border-color:var(--primary);

    transform:translateY(-6px);

}

.workflow-number{

    width:55px;

    height:55px;

    background:var(--primary);

    border-radius:50%;

    display:flex;

    align-items:center;

    justify-content:center;

    margin:auto;

    margin-bottom:20px;

    font-weight:700;

    font-size:20px;

}

.workflow-step h5{

    margin-bottom:10px;

    font-weight:700;

}

.workflow-step p{

    color:var(--muted);

    font-size:14px;

}

/* ==========================================
   CTA
========================================== */

.cta{

    background:#161B22;

    border:1px solid var(--border);

    border-radius:20px;

    text-align:center;

    padding:70px 40px;

}

.cta h2{

    font-size:46px;

    font-weight:700;

}

.cta p{

    color:var(--muted);

    font-size:18px;

    margin:20px auto 35px;

    max-width:650px;

}

/* ==========================================
   FOOTER
========================================== */

footer{

    border-top:1px solid var(--border);

    margin-top:120px;

    padding:70px 0 30px;

    background:#0B0F14;

}

footer h5{

    font-weight:700;

    margin-bottom:15px;

}

footer h6{

    color:white;

    margin-bottom:15px;

}

footer p{

    color:var(--muted);

}

footer a{

    color:var(--muted);

    text-decoration:none;

    line-height:2.2;

    transition:.3s;

}

footer a:hover{

    color:white;

}

.footer-small{

    color:var(--primary);

    font-weight:600;

}

.footer-bottom{

    color:#6B7280;

    text-align:center;

    margin-top:25px;

    font-size:14px;

}

/* ==========================================
   SCROLLBAR
========================================== */

::-webkit-scrollbar{

    width:8px;

}

::-webkit-scrollbar-track{

    background:#0D1117;

}

::-webkit-scrollbar-thumb{

    background:#374151;

    border-radius:20px;

}

::-webkit-scrollbar-thumb:hover{

    background:var(--primary);

}

/* ==========================================
   RESPONSIVE
========================================== */

@media(max-width:992px){

.hero{

    text-align:center;

    min-height:auto;

    padding-top:140px;

}

.hero-image{

    justify-content:center;

    margin-top:60px;

}

.hero h1{

    font-size:54px;

}

.hero h2{

    font-size:24px;

}

.feature-grid{

    grid-template-columns:1fr;

}

.hero-buttons{

    justify-content:center;

}

}

@media(max-width:768px){

.hero h1{

    font-size:42px;

}

.hero p{

    font-size:16px;

}

.section-title h2{

    font-size:34px;

}

.cta h2{

    font-size:32px;

}

}

/* =============================
   Smooth Reveal
============================= */

.feature-card,
.workflow-step,
.cta,
.hero-image,
.section-title{

    opacity:0;

    transform:translateY(40px);

}

.hero-image i{

    transition:.4s;

}
/* ==========================================
   VIVARX BADGE
========================================== */

.project-badge{

    position:relative;

    display:inline-flex;

    align-items:center;

    gap:10px;

    padding:8px 18px;

    background:#161B22;

    border:1px solid #30363D;

    border-radius:30px;

    overflow:hidden;

}

/* Green Live Dot */

.project-badge::before{

    content:"";

    width:8px;

    height:8px;

    border-radius:50%;

    background:#22C55E;

    display:inline-block;

    animation:liveDot 2s infinite;

}

@keyframes liveDot{

    0%,100%{

        opacity:.4;

        box-shadow:0 0 0 rgba(34,197,94,0);

    }

    50%{

        opacity:1;

        box-shadow:0 0 10px rgba(34,197,94,.8);

    }

}

/* Animated VivarX */

.project-name{

    background:linear-gradient(
        90deg,
        #E11D48,
        #FF6A95,
        #E11D48
    );

    background-size:200% auto;

    -webkit-background-clip:text;

    -webkit-text-fill-color:transparent;

    animation:vivarxGradient 4s linear infinite;

    font-weight:700;

}

@keyframes vivarxGradient{

    from{

        background-position:0%;

    }

    to{

        background-position:200%;

    }

}

/* ==========================================
   POWERED BY VIVARX
========================================== */

.project-badge{

    display:inline-flex;
    align-items:center;
    gap:10px;

    background:#161B22;
    border:1px solid #30363D;
    border-radius:30px;

    padding:10px 18px;

    transition:.35s ease;

}

.project-badge::before{

    content:"";

    width:8px;
    height:8px;

    border-radius:50%;

    background:#22C55E;

    animation:statusPulse 2s infinite;

}

.project-badge:hover{

    border-color:#E11D48;

    transform:translateY(-2px);

}

.project-text{

    color:#9AA3B2;

    font-size:14px;

    font-weight:500;

}

.project-name{

    color:#E11D48;

    font-weight:700;

    position:relative;

    overflow:hidden;

}

.project-name::after{

    content:"";

    position:absolute;

    top:0;
    left:-120%;

    width:40%;
    height:100%;

    background:linear-gradient(
        90deg,
        transparent,
        rgba(255,255,255,.9),
        transparent
    );

    transform:skewX(-20deg);

    animation:scanEffect 3s infinite;

}

@keyframes scanEffect{

    0%{
        left:-120%;
    }

    100%{
        left:140%;
    }

}

@keyframes statusPulse{

    0%,100%{

        opacity:.4;
        box-shadow:0 0 0 rgba(34,197,94,0);

    }

    50%{

        opacity:1;
        box-shadow:0 0 10px rgba(34,197,94,.8);

    }

}

/* ==========================================
   UPLOAD PAGE
========================================== */

.upload-page{

    padding-top:140px;
    padding-bottom:100px;

}

.upload-card{

    background:#161B22;
    border:1px solid #30363D;
    border-radius:22px;
    padding:60px;
    text-align:center;
    transition:.35s;

}

.upload-card:hover{

    border-color:#E11D48;
    box-shadow:0 20px 45px rgba(225,29,72,.10);

}

.upload-icon{

    width:90px;
    height:90px;

    border-radius:50%;

    margin:auto;

    display:flex;
    align-items:center;
    justify-content:center;

    background:#1F2937;

    color:#E11D48;

    font-size:42px;

    margin-bottom:30px;

}

.upload-card h3{

    font-weight:700;
    margin-bottom:10px;

}

.upload-card p{

    color:#9AA3B2;

}

.selected-file{

    margin-top:25px;

    color:#CBD5E1;

    font-weight:600;

}

.supported-files{

    margin-top:35px;

}

.supported-files span:first-child{

    color:#9AA3B2;

    font-size:14px;

}

.file-pill{

    display:inline-block;

    padding:8px 15px;

    margin:6px;

    border-radius:30px;

    background:#1C2128;

    border:1px solid #30363D;

    color:#CBD5E1;

    font-size:13px;

}

.file-pill:hover{

    border-color:#E11D48;

    color:white;

}

/* ==========================================
   SECURITY CARDS
========================================== */

.security-box{

    background:#161B22;

    border:1px solid #30363D;

    border-radius:18px;

    padding:35px;

    height:100%;

    transition:.35s;

}

.security-box:hover{

    transform:translateY(-8px);

    border-color:#E11D48;

}

.security-box i{

    font-size:40px;

    color:#E11D48;

    margin-bottom:20px;

}

.security-box h5{

    font-weight:700;

    margin-bottom:15px;

}

.security-box p{

    color:#9AA3B2;

    line-height:1.8;

}

/* ==========================================
   DRAG AREA (Future)
========================================== */

.drop-zone{

    border:2px dashed #30363D;

    border-radius:18px;

    padding:60px;

    transition:.35s;

}

.drop-zone:hover{

    border-color:#E11D48;

}

/* ==========================================
   ANALYZE BUTTON
========================================== */

.upload-card .btn-danger{

    min-width:220px;

    font-weight:600;

    letter-spacing:.5px;

}

/* ==========================================
   RESPONSIVE
========================================== */

@media(max-width:768px){

.upload-card{

    padding:35px 25px;

}

.upload-icon{

    width:70px;
    height:70px;
    font-size:34px;

}

.file-pill{

    margin:4px;

}

.recent-analysis{

    overflow-x:auto;

}

}
/* ==========================================
   ANALYZE BUTTON
========================================== */

.analyze-btn{

    position:relative;

    overflow:hidden;

    min-width:260px;

    height:58px;

    font-weight:600;

    letter-spacing:.5px;

    display:inline-flex;

    align-items:center;

    justify-content:center;

    gap:12px;

}

.analyze-btn i{

    font-size:22px;

}

.analyze-btn::before{

    content:"";

    position:absolute;

    top:0;

    left:-120%;

    width:45%;

    height:100%;

    background:linear-gradient(

        90deg,

        transparent,

        rgba(255,255,255,.45),

        transparent

    );

    transform:skewX(-25deg);

    animation:buttonScan 3s linear infinite;

}

@keyframes buttonScan{

    100%{

        left:160%;

    }

}

.analyze-btn:hover{

    transform:translateY(-3px);

    box-shadow:0 15px 35px rgba(225,29,72,.25);

}

.upload-icon{

    animation:uploadPulse 3s ease-in-out infinite;

}

@keyframes uploadPulse{

    0%,100%{

        transform:scale(1);

        box-shadow:0 0 0 rgba(225,29,72,0);

    }

    50%{

        transform:scale(1.08);

        box-shadow:0 0 20px rgba(225,29,72,.35);

    }

}
/* =====================================================
                INVESTIGATION REPORT
===================================================== */

.dashboard-page{

    padding-top:140px;
    padding-bottom:120px;

}

/* ===========================
   VERDICT CARD
=========================== */

.verdict-card{

    background:linear-gradient(
        135deg,
        #2A1016,
        #161B22
    );

    border:1px solid #E11D48;

    border-radius:20px;

    padding:45px;

    box-shadow:0 20px 45px rgba(225,29,72,.15);

}

.verdict-tag{

    display:inline-block;

    padding:8px 18px;

    background:#E11D48;

    color:white;

    border-radius:30px;

    font-size:13px;

    font-weight:600;

    letter-spacing:1px;

}

.verdict-card h2{

    font-weight:700;

    margin-top:15px;

}

.verdict-card p{

    color:#CBD5E1;

    margin-top:12px;

}

/* ===========================
   RISK SCORE
=========================== */

.risk-circle{

    width:140px;

    height:140px;

    margin-left:auto;

    border-radius:50%;

    border:8px solid #E11D48;

    display:flex;

    align-items:center;

    justify-content:center;

    font-size:34px;

    font-weight:700;

    color:white;

    background:#1C2128;

    box-shadow:0 0 35px rgba(225,29,72,.30);

}

.risk-label{

    display:block;

    margin-top:15px;

    color:#9AA3B2;

    font-size:15px;

}

/* ===========================
   REPORT CARD
=========================== */

.report-card{

    background:#161B22;

    border:1px solid #30363D;

    border-radius:18px;

    padding:30px;

    height:100%;

    transition:.35s;

}

.report-card:hover{

    border-color:#E11D48;

    transform:translateY(-5px);

    box-shadow:0 18px 40px rgba(225,29,72,.12);

}

.report-card h4{

    margin-bottom:25px;

    font-weight:700;

}

/* ===========================
   TABLE
=========================== */

.report-card table{

    margin-bottom:0;

}

.report-card td{

    color:#CBD5E1;

    border-color:#30363D;

}

.report-card th{

    color:white;

    border-color:#30363D;

}
/* ==========================================
   COPY BUTTON
========================================== */

.copy-btn{
    border:none;
    background:#1C2128;
    color:#CBD5E1;
    border:1px solid #30363D;
    border-radius:8px;
    padding:6px 14px;
    font-size:13px;
    transition:.3s;
}

.copy-btn:hover{
    background:#E11D48;
    border-color:#E11D48;
    color:white;
}

/* ==========================================
   ENTROPY
========================================== */

.entropy-item{
    margin-bottom:20px;
}

.entropy-item span{
    display:block;
    margin-bottom:8px;
    font-weight:600;
    color:white;
}

.entropy-item small{
    display:block;
    margin-top:8px;
    color:#9AA3B2;
}

.progress{
    height:10px;
    background:#242B35;
    border-radius:30px;
    overflow:hidden;
}

.progress-bar{
    border-radius:30px;
}

/* ==========================================
   STRINGS
========================================== */

.strings-box{
    display:flex;
    flex-wrap:wrap;
    gap:12px;
}

.string-pill{
    padding:10px 18px;
    border-radius:30px;
    background:#1C2128;
    border:1px solid #30363D;
    color:#CBD5E1;
    font-family:Consolas, monospace;
    transition:.3s;
}

.string-pill:hover{
    border-color:#E11D48;
    background:#23141A;
    color:white;
    transform:translateY(-2px);
}

/* ==========================================
   DOWNLOAD BUTTON
========================================== */

.download-btn{
    min-width:260px;
    height:58px;
    border:none;
    border-radius:10px;
    background:#E11D48;
    color:white;
    font-weight:600;
    display:inline-flex;
    align-items:center;
    justify-content:center;
    gap:12px;
    transition:.35s;
}

.download-btn:hover{
    background:#F43F5E;
    transform:translateY(-3px);
    box-shadow:0 18px 35px rgba(225,29,72,.25);
}

/* ==========================================
   CARD ANIMATION
========================================== */

.report-card{
    animation:reportFade .7s ease;
}

@keyframes reportFade{
    from{
        opacity:0;
        transform:translateY(25px);
    }
    to{
        opacity:1;
        transform:translateY(0);
    }
}

/* ==========================================
   ERROR BOX
========================================== */

.error-box{
    background:#23141A;
    border:1px solid #E11D48;
    border-radius:10px;
    padding:18px;
    color:#F4B4C0;
}

/* ==========================================
   MOBILE
========================================== */

@media(max-width:992px){
    .risk-circle{
        margin:30px auto 0;
    }
    .verdict-card{
        text-align:center;
    }
}

@media(max-width:768px){
    .dashboard-page{
        padding-top:110px;
    }
    .verdict-card{
        padding:30px;
    }
    .risk-circle{
        width:110px;
        height:110px;
        font-size:26px;
    }
    .report-card{
        padding:22px;
    }
    .string-pill{
        width:100%;
        text-align:center;
    }
    .download-btn{
        width:100%;
    }
}

/* ==========================================
   VERDICT SEVERITY VARIANTS
========================================== */

.verdict-tag.risk-high{ background:#E11D48; }
.verdict-tag.risk-medium{ background:#F59E0B; color:#1C2128; }
.verdict-tag.risk-low{ background:#3B82F6; }
.verdict-tag.risk-clean{ background:#22C55E; color:#0D1117; }

.risk-circle.risk-high{ border-color:#E11D48; color:#E11D48; }
.risk-circle.risk-medium{ border-color:#F59E0B; color:#F59E0B; }
.risk-circle.risk-low{ border-color:#3B82F6; color:#3B82F6; }
.risk-circle.risk-clean{ border-color:#22C55E; color:#22C55E; }

/* ==========================================
   GENERIC INNER PAGE HERO
   (Features / Documentation / Contact)
========================================== */

.page-hero{
    padding-top:160px;
    padding-bottom:60px;
}

.page-hero h1{
    font-size:46px;
    font-weight:800;
}

.features-section.pt-0{
    padding-top:20px;
}

@media(max-width:768px){
    .page-hero{
        padding-top:130px;
        padding-bottom:30px;
    }
    .page-hero h1{
        font-size:32px;
    }
}

/* ==========================================
   DOCUMENTATION PAGE
========================================== */

.docs-section{
    padding-bottom:100px;
}

.doc-toc{
    position:sticky;
    top:110px;
    display:flex;
    flex-direction:column;
    gap:10px;
    border-left:1px solid var(--border);
    padding-left:20px;
}

.doc-toc h6{
    color:var(--muted);
    text-transform:uppercase;
    letter-spacing:1px;
    font-size:12px;
    margin-bottom:6px;
}

.doc-toc a{
    color:var(--muted);
    text-decoration:none;
    font-size:14px;
    transition:.25s;
}

.doc-toc a:hover{
    color:white;
    padding-left:4px;
}

.doc-block{
    margin-bottom:55px;
}

.doc-block h3{
    font-size:26px;
    font-weight:700;
    margin-bottom:18px;
    padding-bottom:14px;
    border-bottom:1px solid var(--border);
}

.doc-block h5{
    font-size:17px;
    font-weight:600;
    margin:24px 0 12px;
}

.doc-block p{
    color:var(--muted);
    line-height:1.9;
    margin-bottom:14px;
}

.doc-block code{
    background:var(--card);
    border:1px solid var(--border);
    border-radius:6px;
    padding:2px 8px;
    color:var(--primary);
    font-size:.9em;
}

.doc-block a{
    color:var(--primary);
}

.doc-list{
    color:var(--muted);
    line-height:1.9;
    padding-left:22px;
    margin-bottom:14px;
}

.doc-list li{
    margin-bottom:6px;
}

.doc-code{
    background:var(--card);
    border:1px solid var(--border);
    border-radius:12px;
    padding:22px 24px;
    overflow-x:auto;
    margin-bottom:18px;
}

.doc-code code{
    background:none;
    border:none;
    padding:0;
    color:#CBD5E1;
    font-family:Consolas, monospace;
    font-size:13.5px;
    line-height:1.7;
    white-space:pre;
}

/* ==========================================
   CONTACT CARDS
========================================== */

.contact-card{
    display:block;
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:18px;
    padding:40px;
    text-align:center;
    text-decoration:none;
    color:var(--text);
    height:100%;
    transition:.35s ease;
}

.contact-card:hover{
    transform:translateY(-8px);
    border-color:var(--primary);
    box-shadow:0 18px 40px rgba(225,29,72,.12);
    color:white;
}

.contact-card i{
    font-size:38px;
    color:var(--primary);
    margin-bottom:18px;
    display:block;
}

.contact-card h4{
    font-weight:700;
    margin-bottom:8px;
}

.contact-card p{
    color:var(--muted);
    margin:0;
    word-break:break-word;
}

/* ==========================================
   NAV ACTIVE STATE
========================================== */

.nav-link.active{
    position:relative;
}

.nav-link.active::after{
    content:"";
    position:absolute;
    left:0;
    right:0;
    bottom:-6px;
    height:2px;
    background:var(--primary);
    border-radius:2px;
}

/* ==========================================
   DOCS RESPONSIVE
========================================== */

@media(max-width:992px){
    .doc-toc{
        position:static;
        flex-direction:row;
        flex-wrap:wrap;
        border-left:none;
        border-bottom:1px solid var(--border);
        padding-left:0;
        padding-bottom:20px;
        margin-bottom:30px;
        gap:14px 22px;
    }
}

@media(max-width:768px){
    .doc-block h3{
        font-size:21px;
    }
    .doc-code{
        padding:16px;
    }
    .doc-code code{
        font-size:12px;
    }
    .contact-card{
        padding:28px;
    }
}

/* ==========================================
   PAGE LOAD MOTION
========================================== */

body{
    animation:pageFadeIn .5s ease;
}

@keyframes pageFadeIn{
    from{ opacity:0; }
    to{ opacity:1; }
}

@media(prefers-reduced-motion: reduce){
    *, *::before, *::after{
        animation-duration:.01ms !important;
        animation-iteration-count:1 !important;
        transition-duration:.01ms !important;
        scroll-behavior:auto !important;
    }
}

/* ==========================================
   MOBILE NAV
========================================== */

@media(max-width:991px){
    .navbar-collapse{
        background:rgba(13,17,23,.98);
        margin-top:14px;
        padding:18px;
        border-radius:14px;
        border:1px solid var(--border);
    }
    .navbar-nav{
        align-items:flex-start !important;
        gap:6px;
    }
    .nav-link{
        margin-left:0 !important;
        padding:8px 0;
    }
    .nav-link.active::after{
        display:none;
    }
    .navbar-nav .nav-item.ms-3{
        margin-left:0 !important;
        margin-top:10px;
        width:100%;
    }
    .navbar-nav .nav-item.ms-3 .btn{
        width:100%;
    }
}
```

### static/js/main.js

```javascript
/* ==========================================
   MallnSight UI
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ===========================
       Navbar Scroll Effect
    =========================== */

    const navbar = document.querySelector(".navbar");

    window.addEventListener("scroll", () => {

        if (window.scrollY > 40) {

            navbar.style.background = "rgba(13,17,23,.97)";
            navbar.style.boxShadow = "0 8px 25px rgba(0,0,0,.35)";

        } else {

            navbar.style.background = "rgba(13,17,23,.90)";
            navbar.style.boxShadow = "none";

        }

    });

    /* ===========================
       Reveal Animation
    =========================== */

    const reveals = document.querySelectorAll(
        ".feature-card,.workflow-step,.cta,.hero-image,.section-title," +
        ".doc-block,.contact-card"
    );

    const observer = new IntersectionObserver((entries)=>{

        entries.forEach(entry=>{

            if(entry.isIntersecting){

                entry.target.style.opacity="1";
                entry.target.style.transform="translateY(0px)";

                observer.unobserve(entry.target);

            }

        });

    },{

        threshold:0.15

    });

    reveals.forEach((item,index)=>{

        item.style.opacity="0";
        item.style.transform="translateY(40px)";
        item.style.transition=`opacity .6s cubic-bezier(.16,1,.3,1) ${(index%3)*0.08}s,
                                transform .6s cubic-bezier(.16,1,.3,1) ${(index%3)*0.08}s`;

        observer.observe(item);

    });

    /* ===========================
       Card Hover Tilt
    =========================== */

    document.querySelectorAll(".feature-card").forEach(card=>{

        card.addEventListener("mousemove",(e)=>{

            const rect = card.getBoundingClientRect();

            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            const rotateX = (y - rect.height/2)/25;
            const rotateY = -(x - rect.width/2)/25;

            card.style.transform=
                `perspective(800px)
                rotateX(${rotateX}deg)
                rotateY(${rotateY}deg)
                translateY(-6px)`;

        });

        card.addEventListener("mouseleave",()=>{

            card.style.transform="translateY(0px)";

        });

    });

    /* ===========================
       Hero Icon Pulse
    =========================== */

    const heroIcon = document.querySelector(".hero-image i");

    if(heroIcon){

        setInterval(()=>{

            heroIcon.animate([

                {
                    transform:"scale(1)"
                },

                {
                    transform:"scale(1.08)"
                },

                {
                    transform:"scale(1)"
                }

            ],{

                duration:1800

            });

        },3500);

    }

});
```

---

## Tests

### tests/test_app.py

```python
import io
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.mark.parametrize("route", ["/", "/about", "/features", "/upload", "/contact", "/history"])
def test_static_pages_load(client, route):
    response = client.get(route)
    assert response.status_code == 200


def test_analyze_requires_a_file(client):
    response = client.post("/analyze", data={})
    assert response.status_code == 400


def test_analyze_rejects_get(client):
    response = client.get("/analyze")
    assert response.status_code == 405


def test_analyze_rejects_disallowed_extension(client):
    data = {
        "file": (io.BytesIO(b"hello world"), "notes.txt")
    }
    response = client.post("/analyze", data=data, content_type="multipart/form-data")
    assert response.status_code == 400


def test_history_degrades_gracefully_without_mongodb_uri(client, monkeypatch):
    from analysis import history

    monkeypatch.delenv("MONGODB_URI", raising=False)
    history._reset_cache()

    response = client.get("/history")

    assert response.status_code == 200
    assert b"unavailable" in response.data.lower()

    history._reset_cache()


def test_analyze_accepts_pe_file(client):
    pe_path = os.path.join(os.path.dirname(sys.executable), "python.exe")

    if not os.path.exists(pe_path):
        pytest.skip("No PE binary available to test with on this platform")

    with open(pe_path, "rb") as f:
        data = {
            "file": (io.BytesIO(f.read()), "sample.exe")
        }
        response = client.post("/analyze", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    assert b"Risk Score" in response.data
```

---

## Configuration

### requirements.txt

```text
blinker==1.9.0
click==8.4.2
Flask==3.1.3
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.3
pefile==2024.8.26
pymongo==4.17.0
python-dotenv==1.2.2
reportlab==5.0.0
waitress==3.0.2
Werkzeug==3.1.8
yara-python==4.5.4
```

### .env.example

```text
# Copy this file to .env and fill in your own values.
# .env is gitignored — never commit real credentials.

# MongoDB Atlas connection string (used for the /history cloud feature).
# Get this from your Atlas cluster: Database > Connect > Drivers.
# Example: mongodb+srv://<user>:<password>@<cluster-host>/?retryWrites=true&w=majority
MONGODB_URI=

# Optional: database name (defaults to "mallnsight" if not set)
MONGODB_DB=mallnsight

# Optional: enable Flask debug mode locally (never enable in production)
FLASK_DEBUG=0
```

### Procfile

```text
web: waitress-serve --host=0.0.0.0 --port=$PORT app:app
```

### runtime.txt

```text
python-3.12.7
```

---
