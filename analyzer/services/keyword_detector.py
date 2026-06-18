import re

PHISHING_KEYWORDS = {
    "urgency": {
        "weight" : 3, # key : value
        "words" : [ # key : list of keywords
            "immediately", "within 24 hours", "urgent", "action required",
            "suspended", "blocked", "closed", "terminated", "critical limit",
            "asap", "final notice", "expiration", "deactivated"
        ]
    },
    "financial" : {
        "weight" : 2,
        "words" : [
            "invoice", "payment", "refund", "wire transfer", "bank transfer",
            "receipt", "overdue", "billing", "credit card", "transaction",
            "payroll", "purchase order"
        ]
    },
    "security_alert" : {
        "weight" : 2,
        "words" : [
            "unauthorized access", "security alert", "suspicious login",
            "reset password", "verification code", "compromised", "identity theft",
            "login attempt", "security department"
        ]
    },
    "call_to_action" :{
        "weight" : 1,
        "words" : [
            "click here", "verify now", "login below", "confirm identity",
            "update account", "link below", "access your account", "verify account"
        ]
    }
}


# Makes text easier to analyze by: Converting everything to lowercase, Removing extra spaces, Removing punctuation

def clean_and_normalize(text):
    """
        Normalizes the text: converts to lowercase, strips extra whitespace,
        and removes simple punctuation.
        """
    if not text:
        return ""

    text = text.lower() # convert all the text eitehr it is a subject or a body into lowercase

    text = re.sub(r'\s+', ' ', text) # \s remove white space, + = one or more
    text = re.sub(r'[^\w\s]', '', text) # this line remove punctuation/ special character from the text, like "Urgent! Action-Required."
    # to "Urgent ActionRequired"

    return  text.strip() # remove space before, after and return the clean text, that can be matched to above keywords directory


def detect_keywords(subject,body_text):
    """
        Scans the subject and body text for phishing keywords.
        Subject matches are given a 1.5x multiplier.
        Returns a dictionary containing:
            - keyword_score (int: 0 to 15)
            - matched_keywords (list of strings)
            - categories_found (list of strings)
        """
    clean_subject = clean_and_normalize(subject)
    clean_body = clean_and_normalize(body_text)

    score = 0.0
    matched_words = set()
    matched_categories = set()

    # If both inputs are empty, return default safe values
    if not clean_subject and not clean_body:
        return {
            "keyword_score": 0,
            "matched_keywords": [],
            "categories_found": []
        }

    # Iterate through each category
    for category, config in PHISHING_KEYWORDS.items():  # category is key like urgency, financial, security_alert, call_to_action, and congig is the value
        weight = config["weight"]
        words = config["words"]

        for word in words:
            # Clean/normalize the target keyword to ensure matching works
            # In the above PHISHING_KEYWORDS, all words are already normalized, this works if we add other not normalized words
            normalized_word = clean_and_normalize(word)

            found_in_subject = False
            found_in_body = False

            # Check Subject (1.5x Weight)
            if clean_subject and normalized_word in clean_subject:
                # Check if the subject exists and contains the current phishing keyword.
                found_in_subject = True
                score += (weight * 1.5)
                matched_words.add(f"{word} (subject)")

            # Check Body (1.0x Weight)
            if clean_body and normalized_word in clean_body:
                # Check if the body exists and contains the current phishing keyword.
                    found_in_body = True
                    score += (weight * 1.0)
                    matched_words.add(f"{word} (body)")

                # If a keyword from this category was found in either the subject or body, record the category name (urgency, financial, security_alert,.....).
            if found_in_subject or found_in_body:
                matched_categories.add(category)

    # Round the calculated score and make sure it never exceeds 15 points. Combining with other module header_analyzer, ioc_extractor, ma_classifier, we can relate to 100
    final_score = min(int(round(score)), 15)

    return {
        # Return the final keyword score, matched keywords, and detected phishing categories.
        "keyword_score": final_score,
        "matched_keywords": sorted(list(matched_words)),
        "categories_found": sorted(list(matched_categories))
    }
