import logging

logger = logging.getLogger(__name__)


def calculate_risk(auth_score, keyword_score, ioc_score, ml_score):
    """
    Aggregates the individual analyzer scores into a single threat score out of 100.

    Inputs:
        - auth_score    (int: 0 to 30)  — from header_analyzer.py
        - keyword_score (int: 0 to 15)  — from keyword_detector.py
        - ioc_score     (int: 0 or 35)  — from threat_intel.py
        - ml_score      (int: 0 to 100) — from ml_classifier.py

    Returns:
        - risk_score (int: 0 to 100)

    Formula:
        Case A (IOCs present):
            risk = auth + ioc + keywords + (ml * 0.20)
        Case B (No IOCs):
            risk = (auth * 1.2) + (keywords * 1.6) + (ml * 0.40)
    """
    # Clamp all scores to their design boundaries to prevent calculation errors
    # and guard against None values from crashed upstream modules.
    auth = min(max(int(auth_score or 0), 0), 30)
    keywords = min(max(int(keyword_score or 0), 0), 15)
    ioc = min(max(int(ioc_score or 0), 0), 35)
    ml = min(max(int(ml_score or 0), 0), 100)

    if ioc > 0:
        # Case A: Standard Weighted Formula — active IOCs found
        raw_score = auth + ioc + keywords + (ml * 0.20)
    else:
        # Case B: Scaled Formula — no IOCs; boost header and text-layer weight
        raw_score = (auth * 1.2) + (keywords * 1.6) + (ml * 0.40)

    # Round to nearest integer and cap strictly between 0 and 100
    final_score = min(max(int(round(raw_score)), 0), 100)
    logger.debug(
        "calculate_risk | auth=%d kw=%d ioc=%d ml=%d -> raw=%.2f final=%d",
        auth, keywords, ioc, ml, raw_score, final_score,
    )
    return final_score


def determine_verdict(risk_score):
    """
    Maps the risk score (0–100) to a human-readable security verdict.

    Thresholds:
        0  – 30  →  SAFE
        31 – 60  →  SUSPICIOUS
        61 – 100 →  MALICIOUS
    """
    if risk_score <= 30:
        return "SAFE"
    elif risk_score <= 60:
        return "SUSPICIOUS"
    else:
        return "MALICIOUS"


def determine_classification(risk_score, categories_found, matched_keywords):
    """
    Assigns a broad classification and a phishing sub-category based on
    the keyword evidence collected by keyword_detector.py.

    Args:
        risk_score       (int)       — computed risk percentage
        categories_found (list[str]) — e.g. ['urgency', 'call_to_action']
        matched_keywords (list[str]) — individual keyword matches

    Returns:
        (classification: str, phishing_type: str | None)
    """
    if risk_score <= 30:
        return "Clean", None

    # Normalise for case-insensitive matching
    keywords_lower = [k.lower() for k in (matched_keywords or [])]
    categories_lower = [c.lower() for c in (categories_found or [])]

    # No keyword evidence → classify as general spam
    if not categories_lower:
        return "Spam", "General Spam"

    # Rule 1: Fake Invoice / Billing — financial category is definitive
    if "financial" in categories_lower:
        return "Phishing", "Fake Invoice"

    # Rule 2: Account Suspension — explicit suspension-related keywords
    suspension_words = {"suspended", "blocked", "deactivated"}
    if suspension_words.intersection(keywords_lower):
        return "Phishing", "Account Suspension"

    # Rule 3: Credential Harvesting — CTA + security alert pair
    if "call_to_action" in categories_lower and "security_alert" in categories_lower:
        return "Phishing", "Credential Harvesting"

    # Rule 4: Delivery / Postal Scam
    delivery_words = {"shipping", "package", "tracking", "post office", "delivery"}
    if delivery_words.intersection(keywords_lower):
        return "Phishing", "Delivery Scam"

    # Default fallback
    return "Phishing", "General Phishing"


def analyze_threat_risk(auth_data, keyword_data, ioc_score, ml_score):
    """
    Master coordinator function.  Gathers outputs from all individual analyzers,
    calculates the total risk, and returns a structured result dict.

    Args:
        auth_data    (dict) — returned by analyze_headers()
                              expected keys: 'auth_score'
        keyword_data (dict) — returned by detect_keywords()
                              expected keys: 'keyword_score', 'categories_found',
                                            'matched_keywords'
        ioc_score    (int)  — 0 or 35, returned by update_email_iocs()
        ml_score     (int)  — 0–100, returned by classify()

    Returns:
        {
            "risk_score":      int,        # 0–100
            "verdict":         str,        # SAFE | SUSPICIOUS | MALICIOUS
            "classification":  str,        # Clean | Spam | Phishing
            "phishing_type":   str | None  # sub-category or None for Clean
        }
    """
    # Safely extract scores; default to 0 if a module returned an incomplete dict
    auth_score = auth_data.get("auth_score", 0) if auth_data else 0
    keyword_score = keyword_data.get("keyword_score", 0) if keyword_data else 0
    categories_found = keyword_data.get("categories_found", []) if keyword_data else []
    matched_keywords = keyword_data.get("matched_keywords", []) if keyword_data else []

    # 1. Compute risk percentage
    risk_score = calculate_risk(auth_score, keyword_score, ioc_score, ml_score)

    # 2. Determine security verdict
    verdict = determine_verdict(risk_score)

    # 3. Classify phishing sub-category
    classification, phishing_type = determine_classification(
        risk_score, categories_found, matched_keywords
    )

    logger.info(
        "analyze_threat_risk | score=%d verdict=%s classification=%s type=%s",
        risk_score, verdict, classification, phishing_type,
    )

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "classification": classification,
        "phishing_type": phishing_type,
    }
