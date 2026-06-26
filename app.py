import os
import uuid

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


@app.route("/download/<download_id>")
def download_report(download_id):
    report_path = _generated_reports.get(download_id)

    if not report_path or not os.path.exists(report_path):
        abort(404)

    return send_file(report_path, as_attachment=True, download_name="MallnSight_Report.pdf")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)