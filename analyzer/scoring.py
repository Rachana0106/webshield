CATEGORY_WEIGHTS = {
    "Transport Security": 22, "Browser Security": 22, "Cookie Security": 12,
    "Form Security": 10, "Cross-Origin Security": 10, "Third-Party Resources": 8,
    "Information Exposure": 8, "Client-Side Review": 8,
}
SEVERITY_DEDUCTION = {"Critical": 38, "High": 26, "Medium": 13, "Low": 5, "Info": 0}
CONFIDENCE = {"High": 1.0, "Medium": .70, "Low": .40}
STATUS = {
    "Confirmed Configuration Finding": 1.0, "Probable Finding": .75,
    "Potential Concern": .45, "Manual Review Required": .15, "Informational": 0.0,
}

def _category_score(category, findings):
    deduction = 0.0
    for f in findings:
        if f.get("category") != category:
            continue
        deduction += (SEVERITY_DEDUCTION.get(f.get("severity","Info"),0)
                      * CONFIDENCE.get(f.get("confidence","Low"),.4)
                      * STATUS.get(f.get("status","Manual Review Required"),.15))
    return max(0, round(100 - min(100, deduction)))

def calculate_scores(findings, evidence):
    categories = {}
    for name in CATEGORY_WEIGHTS:
        ev = evidence.get(name, {})
        state = ev.get("state", "limited")
        categories[name] = {
            "state": state,
            "score": _category_score(name, findings) if state == "evaluated" else None,
            "note": ev.get("note", ""),
        }

    evaluated = {k:v for k,v in categories.items() if v["state"] == "evaluated"}
    ew = sum(CATEGORY_WEIGHTS[k] for k in evaluated)
    tw = sum(CATEGORY_WEIGHTS.values())
    coverage = ew / tw if tw else 0

    raw = None if not evaluated else round(
        sum(v["score"] * CATEGORY_WEIGHTS[k] for k,v in evaluated.items()) / ew
    )
    # Low coverage lowers confidence in the overall number without inventing unseen failures.
    score = None if raw is None else max(0, raw - round((1-coverage)*12))

    confirmed = [f for f in findings if f.get("status") == "Confirmed Configuration Finding"]
    counts = {s.lower(): sum(f.get("severity")==s for f in confirmed)
              for s in ("Critical","High","Medium","Low")}

    # Serious directly observed findings cap reassuring averages.
    if score is not None:
        if counts["critical"]: score = min(score, 39)
        elif counts["high"] >= 2: score = min(score, 49)
        elif counts["high"] == 1: score = min(score, 59)
        elif counts["medium"] >= 3: score = min(score, 69)

    if score is None: posture = "INSUFFICIENT EVIDENCE"
    elif score >= 90: posture = "STRONG OBSERVED POSTURE"
    elif score >= 75: posture = "GOOD OBSERVED POSTURE"
    elif score >= 60: posture = "NEEDS IMPROVEMENT"
    elif score >= 40: posture = "WEAK OBSERVED POSTURE"
    else: posture = "HIGH-RISK OBSERVED POSTURE"

    return {
        "score": score, "raw_score": raw, "posture": posture,
        "posture_text": posture.replace("_"," ").title(),
        "categories": categories, "coverage_percent": round(coverage*100),
        "evaluated_count": len(evaluated), "total_categories": len(CATEGORY_WEIGHTS),
        "confirmed_counts": counts,
    }
