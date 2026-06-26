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
