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
