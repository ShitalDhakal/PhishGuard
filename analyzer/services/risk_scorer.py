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
                          (model trained on Zero-Day_Phishing_Emails_Corpus.csv)
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

    # Ensure the authentication score contributes a maximum of 30 points and never falls below 0.
    auth = min(max(int(auth_score or 0), 0), 30)

    keywords = min(max(int(keyword_score or 0), 0), 15)
    ioc = min(max(int(ioc_score or 0), 0), 35)
    ml = min(max(int(ml_score or 0), 0), 100)

    if ioc > 0:
        #  Case A: Standard Weighted Formula when active IOCs found in the email
        """
        This checks that threat intelligence find a blacklisted link/malicious IP address or not.
        If yes, ioc will be 35 (which is greater than 0), 
        and Python runs below code."""
        raw_score = auth + ioc + keywords + (ml * 0.20)

    else:
        # Case B: Scaled Formula -> no IOCs; scale header and text-layer weight.
        # ml weight doubles (0.20 → 0.40) because the phishing email ML model
        # is the strongest text-layer signal when no malicious links are present.
        raw_score = (auth * 1.2) + (keywords * 1.6) + (ml * 0.40)

    # Round to nearest integer and cap strictly between 0 and 100
    final_score = min(max(int(round(raw_score)), 0), 100)
    # Record the authentication, keyword, IOC, ML, and final risk scores to help debug the phishing risk calculation.
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

    Supported sub-categories (Step 12):
        Banking Fraud, Reward Scam, Fake Invoice, Account Suspension,
        Credential Harvesting, Delivery Scam, General Phishing,
        General Spam, Clean

    Args:
        risk_score       (int)       — computed risk percentage
        categories_found (list[str]) — e.g. ['urgency', 'banking_fraud']
        matched_keywords (list[str]) — individual keyword matches

        Returns:
        (classification: str, phishing_type: str | None)
    """
    if risk_score <= 30:
        return "Clean", None

    # Convert all matched keywords to lowercase.
    keywords_lower = []

    if matched_keywords:
        for keyword in matched_keywords:
            keywords_lower.append(keyword.lower())

    # Convert all detected categories to lowercase.
    categories_lower = []

    if categories_found:
        for category in categories_found:
            categories_lower.append(category.lower())

    # No keyword evidence → classify as general spam
    if not categories_lower:
        return "Spam", "General Spam"

    # Rule 1: Banking Fraud — bank/financial institution impersonation
    # Triggered by the 'banking_fraud' keyword category in keyword_detector.py.
    # Covers: ATM, PIN, Social Security, routing numbers, account review depts.
    if "banking_fraud" in categories_lower:
        return "Phishing", "Banking Fraud"

    # Rule 2: Reward Scam — prize/lottery/gift social engineering
    # Triggered by the 'reward_scam' keyword category in keyword_detector.py.
    # Covers: lottery, prize, cash reward, congratulations winner.
    if "reward_scam" in categories_lower:
        return "Phishing", "Reward Scam"

    # Rule 3: Fake Invoice / Billing — financial category is definitive
    if "financial" in categories_lower:
        return "Phishing", "Fake Invoice"

    # Rule 4: Account Suspension — explicit suspension/locking keywords
    # Uses set intersection for O(1) average-case lookups.
    suspension_words = {"suspended", "blocked", "deactivated", "locked",
                        "too many failed", "profile has been locked",
                        "account has been locked"}
    if suspension_words.intersection(keywords_lower):
        return "Phishing", "Account Suspension"

    # Rule 5: Credential Harvesting — CTA + security alert pair
    if "call_to_action" in categories_lower and "security_alert" in categories_lower:
        return "Phishing", "Credential Harvesting"

    # Rule 6: Delivery / Postal Scam
    delivery_words = {"shipping", "package", "tracking", "post office",
                      "delivery", "courier", "parcel", "dispatch"}
    if delivery_words.intersection(keywords_lower):
        return "Phishing", "Delivery Scam"

    # Default fallback
    return "Phishing", "General Phishing"





def analyze_threat_risk(auth_data, keyword_data, ioc_score, ml_score):
    """
        Master coordinator function. Gathers outputs from all individual analyzers,
        calculates the total risk, and returns a structured result dict.

        Args:
            auth_data    (dict) — returned by analyze_headers()
                                  expected keys: 'auth_score'
            keyword_data (dict) — returned by detect_keywords()
                                  expected keys: 'keyword_score', 'categories_found',
                                                'matched_keywords'
            ioc_score    (int)  — 0 or 35, returned by update_email_iocs()
            ml_score     (int)  — 0–100, returned by classify()
                                  (phishing email model — not SMS spam model)

        Returns:
            {
                "risk_score":      int,        # 0–100
                "verdict":         str,        # SAFE | SUSPICIOUS | MALICIOUS
                "classification":  str,        # Clean | Spam | Phishing
                "phishing_type":   str | None  # sub-category or None for Clean
            }
        """

    # Safely extract scores; default to 0 if a module returned an incomplete dict

    auth_score = 0
    keyword_score = 0
    categories_found = []
    matched_keywords = []


    if auth_data: # check if auth_data is not empty (None)
        auth_score = auth_data.get("auth_score", 0) # If data is empty, initilize to default 0

    if keyword_data: # checks whether keyword_data exists (is not None or empty).
        # Suppose "keyword_score": 12, then, keyword_score is initilized as 12
        keyword_score = keyword_data.get("keyword_score", 0)
        categories_found = keyword_data.get("categories_found", []) # Look for this key in the dictionary. If it exists, return its value. Otherwise, return the default value.
        matched_keywords = keyword_data.get("matched_keywords", [])

    # 1. Compute risk percentage
    risk_score = calculate_risk(auth_score, keyword_score, ioc_score, ml_score)

    # 2. Determine security verdict
    verdict = determine_verdict(risk_score)

    # 3. Classify phishing sub-category
    classification, phishing_type = determine_classification(
        risk_score, categories_found, matched_keywords
    )

    # Log the final threat analysis results, including the risk score, verdict, email classification, and detected phishing type.
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




if __name__ == "__main__":
    # Configure logging to display INFO messages in the console.
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print("========== Threat Risk Scorer Tests ==========\n")

    test_cases = [
        {
            "name": "Clean Email",
            "auth": {"auth_score": 0},
            "keyword": {
                "keyword_score": 0,
                "categories_found": [],
                "matched_keywords": [],
            },
            "ioc": 0,
            "ml": 5,
        },
        {
            "name": "Banking Fraud",
            "auth": {"auth_score": 15},
            "keyword": {
                "keyword_score": 10,
                "categories_found": ["banking_fraud"],
                "matched_keywords": ["ATM", "PIN", "routing number"],
            },
            "ioc": 0,
            "ml": 80,
        },
        {
            "name": "Reward Scam",
            "auth": {"auth_score": 10},
            "keyword": {
                "keyword_score": 8,
                "categories_found": ["reward_scam"],
                "matched_keywords": ["congratulations", "winner", "prize"],
            },
            "ioc": 35,
            "ml": 75,
        },
        {
            "name": "Account Suspension",
            "auth": {"auth_score": 20},
            "keyword": {
                "keyword_score": 12,
                "categories_found": ["urgency"],
                "matched_keywords": ["profile has been locked", "suspended"],
            },
            "ioc": 0,
            "ml": 90,
        },
        {
            "name": "Credential Harvesting",
            "auth": {"auth_score": 15},
            "keyword": {
                "keyword_score": 11,
                "categories_found": ["call_to_action", "security_alert"],
                "matched_keywords": ["verify now", "click here", "suspicious activity"],
            },
            "ioc": 0,
            "ml": 85,
        },
        {
            "name": "Delivery Scam",
            "auth": {"auth_score": 10},
            "keyword": {
                "keyword_score": 7,
                "categories_found": ["delivery"],
                "matched_keywords": ["shipping", "parcel", "tracking"],
            },
            "ioc": 0,
            "ml": 75,
        },
        {
            "name": "General Spam",
            "auth": {"auth_score": 5},
            "keyword": {
                "keyword_score": 4,
                "categories_found": [],
                "matched_keywords": [],
            },
            "ioc": 0,
            "ml": 55,
        },
        {
            "name": "Empty Inputs Guard",
            "auth": None,
            "keyword": None,
            "ioc": 0,
            "ml": 0,
        },
    ]

    for index, test in enumerate(test_cases, start=1):
        result = analyze_threat_risk(
            auth_data=test["auth"],
            keyword_data=test["keyword"],
            ioc_score=test["ioc"],
            ml_score=test["ml"],
        )

        print(f"Test {index}: {test['name']}")
        print(f"Result: {result}\n")

    print("========== All Tests Completed ==========")
