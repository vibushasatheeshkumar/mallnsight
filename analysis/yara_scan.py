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
