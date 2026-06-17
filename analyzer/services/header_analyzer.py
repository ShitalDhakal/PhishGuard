from analyzer.services.email_parser import parse_email_address
# is used in header_analyzer.py to reuse the email address parser I wrote in email_parser.py.


def check_spf(received_spf):
    """
    Analyzes the Received-SPF header value.
    Returns (score, result_string).
    Example (8, "fail")
    """
    if not received_spf:
        return 3, "missing"

    spf_lower = received_spf.lower() # The SPF result will be in form 'PASS', this line change into lowercase

    if "fail" in spf_lower and "softfail" not in spf_lower: # "softfail" contains the word "fail", and we only want to detect a real SPF failure (spf=fail), not a soft failure (spf=softfail).`
        return 8, "fail"
    elif "softfail" in spf_lower: # The domain owner is saying: "This sender is probably not authorized."
        return 4, "softfail"
    elif "pass" in spf_lower:
        return 0, "pass"
    else:
        return 3, "unknown"


def check_dkim(dkim_signature):
    """
    This function checks whether the email contains a DKIM-Signature header.
    Absence of DKIM on emails claiming to be from major providers is suspicious.
    Returns (score, result_string).
    """
    if not dkim_signature:
        return 5, "missing"

    return 0, "present"


def check_dmarc(dmarc):
    """
    Analyzes the DMARC result extracted from Authentication-Results.
    DMARC uses SPF and DKIM results to determine whether an email is truly from the claimed domain.
    Returns (score, result_string).
    """
    if not dmarc:
        return 3, "missing"

    dmarc_lower = dmarc.lower()

    if "fail" in dmarc_lower:
        return 7, "fail"
    elif "pass" in dmarc_lower:
        return 0, "pass"
    else:
        return 3, "unknown"


def check_reply_to_mismatch(parsed_data):
    """
    Compares the domain in From vs Reply-To.
    A mismatch means replies go to a different domain than the sender — common in phishing.
    Returns (score, is_mismatch).
    """
    sender_domain = parsed_data["sender"]["domain"].lower()
    reply_to_domain = parsed_data["reply_to"]["domain"].lower()

    # If Reply-To is empty, there's no mismatch to detect
    if not reply_to_domain:
        return 0, False

    if sender_domain and reply_to_domain and sender_domain != reply_to_domain: # this becomes, if True and True and True:
        return 5, True

    return 0, False

# # Detect emails where the Return-Path domain differs from the sender's domain.
def check_return_path_mismatch(parsed_data):
    """
    Compares the domain in From vs Return-Path.
    A mismatch indicates the email was sent through a different system than claimed.
    Returns (score, is_mismatch).
    In phishing emails, attackers often make the email appear to come from one domain,
    but the actual mail server returning bounced emails belongs to another domain.
    """
    sender_domain = parsed_data["sender"]["domain"].lower()

    if not parsed_data.get("return_path"):
        return 0, False

    return_path_parsed = parse_email_address(parsed_data["return_path"])
    return_path_domain = return_path_parsed["domain"].lower()

    if not return_path_domain:
        return 0, False

    if sender_domain and return_path_domain and sender_domain != return_path_domain:
        return 4, True

    return 0, False

def check_x_mailer(x_mailer):
    """
    Checks the X-Mailer header for suspicious sending tools.
    Returns (score, tool_name or None).
    """
    if not x_mailer:
        return 0, None

    suspicious_tools = [
        "phpmailer",
        "swiftmailer",
        "mass mailer",
        "bulk mail",
        "sendblaster",
        "mailchimp",       # Legitimate, but unusual for personal emails
        "campaign monitor",
    ]

    mailer_lower = x_mailer.lower()

    for tool in suspicious_tools:
        if tool in mailer_lower:
            return 5, x_mailer

    return 0, None

def check_received_chain(received_chain):
    """
    Analyzes the Received headers for anomalies:
    - Too many hops (> 8) suggests proxy routing to hide origin
    Returns (score, hop_count).
    """
    if not received_chain:
        return 0, 0

    hop_count = len(received_chain)

    if hop_count > 8:
        return 3, hop_count

    return 0, hop_count

def analyze_headers(parsed_data):
    """
    Master function — runs all header checks on the parsed email dictionary.
    Returns a dictionary with the total auth_score and detailed findings.

    Input: The dictionary returned by parse_email() from email_parser.py
    Output: {
        "auth_score": 0-30,
        "findings": { detailed results of each check }
    }
    """
    total_score = 0
    findings = {}

    # 1. SPF Check
    spf_score, spf_result = check_spf(parsed_data.get("received_spf"))
    total_score += spf_score
    findings["spf"] = {"result": spf_result, "score": spf_score}
    """
    Store the SPF check result inside the findings dictionary.
    After check it looks like:
    
    findings["spf"] = {
    "result": "fail",
    "score": 5
    }
    """

    # 2. DKIM Check
    dkim_score, dkim_result = check_dkim(parsed_data.get("dkim_signature"))
    total_score += dkim_score
    findings["dkim"] = {"result": dkim_result, "score": dkim_score}

    # 3. DMARC Check
    dmarc_score, dmarc_result = check_dmarc(parsed_data.get("dmarc"))
    total_score += dmarc_score
    findings["dmarc"] = {"result": dmarc_result, "score": dmarc_score}

    # 4. Reply-To Mismatch
    reply_score, reply_mismatch = check_reply_to_mismatch(parsed_data)
    total_score += reply_score
    findings["reply_to_mismatch"] = {"detected": reply_mismatch, "score": reply_score}

    # 5. Return-Path Mismatch
    rp_score, rp_mismatch = check_return_path_mismatch(parsed_data)
    total_score += rp_score
    findings["return_path_mismatch"] = {"detected": rp_mismatch, "score": rp_score}

    # 6. X-Mailer Check
    mailer_score, suspicious_tool = check_x_mailer(parsed_data.get("x_mailer"))
    total_score += mailer_score
    findings["x_mailer"] = {"suspicious_tool": suspicious_tool, "score": mailer_score}

    # 7. Received Chain Check
    chain_score, hop_count = check_received_chain(parsed_data.get("received_chain"))
    total_score += chain_score
    findings["received_chain"] = {"hop_count": hop_count, "score": chain_score}

    """
    After all checks
    It may look like:
    findings = {
    "spf": {
        "result": "fail",
        "score": 5
    },
    "dkim": {
        "result": "missing",
        "score": 4
    },
    "dmarc": {
        "result": "fail",
        "score": 5
    }
   }
    """

    # Cap the score at 30. This header parser score is out of 30, which after combining with other analysis modules will sum to a total risk score out of 100.
    total_score = min(total_score, 30)

    return {
        "auth_score": total_score,
        "findings": findings,
    }
