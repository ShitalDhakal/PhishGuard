import os
import time  # Use for VirusTotal, Waits for 15 seconds, to avoid rate limiting
import base64  # URLs to be Base64 URL-safe encoded before querying them
import requests
from analyzer.models import IOC

# Load API keys from environment
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
MALWAREBAZAAR_API_KEY        = os.getenv("MALWAREBAZAAR_API_KEY")
VIRUSTOTAL_API_KEY           = os.getenv("VIRUSTOTAL_API_KEY")



# LAYER 1 — DATABASE CACHE
def get_cached_ioc_result(ioc_type, value):
    """
    Performs a GLOBAL lookup in the PostgreSQL database to check whether
    this exact IOC value has already been resolved in any previous email.

    WHY THIS EXISTS:
    In a phishing campaign, the same malicious URL or IP hits many employees.
    Without this check, every email generates an independent API call for
    the same value. This layer reuses previously stored results instantly,
    consuming zero API quota.

    The lookup is by (ioc_type + value) across ALL emails — not just the
    current one. So if "evil.com" was resolved for Email #1, all future
    emails with the same domain skip all API calls and return immediately.

    Args:
        ioc_type (str): "ip", "url", "domain", or "hash"
        value    (str): The IOC value, e.g. "192.168.1.1" or "http://evil.com"

    Returns:
        tuple: (is_malicious: bool, threat_score: int, found: bool)
            found=True  → cached result found, use it
            found=False → not seen before, proceed to Layer 2
    """
    existing = IOC.objects.filter(
        ioc_type=ioc_type,
        value=value,
        is_scanned=True  # Only rows with a finalized, stored result
    ).first()
    if existing is not None:
        return existing.is_malicious, existing.threat_score, True

    return False, 0, False # Return the cached IOC reputation if found; otherwise indicate that no cached result exists.




# LAYER 2A — AbuseIPDB (for IP addresses)
def check_ip_reputation(ip_address):
    """
    Queries AbuseIPDB for IP address reputation.

    AbuseIPDB is a crowdsourced database where security professionals submit
    reports about IPs observed performing malicious activity — spam, DDoS,
    brute-force logins, port scans, phishing hosting, etc.

    API Endpoint : GET https://api.abuseipdb.com/api/v2/check
    Free Quota   : 1,000 checks per day (not per-minute limited)
    Documentation: https://docs.abuseipdb.com/#check-endpoint

    Response includes "abuseConfidenceScore" (0-100):
        0   = No reports, likely clean
        25+ = Reported abusive — treated as malicious by PhishGuard
        100 = Confirmed malicious by many reporters

    Args:
        ip_address (str): IP to check, e.g. "45.33.32.156"

    Returns:
        tuple: (is_malicious: bool, score: int)
    """
    if not ABUSEIPDB_API_KEY:
        return False, 0

    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip_address, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data  = response.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            return (score >= 25), score
        return False, 0
    except Exception:
        return False, 0





# LAYER 2B — Google Safe Browsing (for URLs and Domains)
def check_gsb_reputation(value):
    """
    Queries the Google Safe Browsing Lookup API v4 to check a URL or domain.

    WHY GOOGLE SAFE BROWSING INSTEAD OF VIRUSTOTAL FOR URLS/DOMAINS:
    Google Safe Browsing is specifically designed for phishing and malware
    web page detection — exactly what PhishGuard needs. It has a dedicated
    "SOCIAL_ENGINEERING" threat type which is the technical classification
    for phishing. It is used natively by Chrome, Firefox, Safari, and Gmail
    itself to block malicious links.

    Quota   : 10,000 requests per day — no per-minute rate limit
    API Key : Free via Google Cloud Console (enable "Safe Browsing API")
    Docs    : https://developers.google.com/safe-browsing/v4/lookup-api

    Threat types checked:
    - MALWARE              → pages that install malware
    - SOCIAL_ENGINEERING   → phishing pages (credential harvesting, fake login)
    - UNWANTED_SOFTWARE    → pages with potentially unwanted programs

    Args:
        value (str): URL or domain to check, e.g. "http://evil.com/login"

    Returns:
        tuple: (is_malicious: bool, score: int, found: bool)
            found=True  → Google has a record of this threat
            found=False → not in Google's database, proceed to Layer 3
    """
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return False, 0, False

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    headers = {"Content-Type": "application/json"}

    payload = {
        "client": {
            "clientId":      "phishguard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": value}]
        }
    }

    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=10)

        if response.status_code == 200:
            data    = response.json()
            matches = data.get("matches", [])

            if matches:
                # Google found a threat record for this URL/domain
                print(f"[GSB HIT] {value} — threat type: {matches[0].get('threatType')}")
                return True, 100, True

            # GSB responded but found nothing — URL/domain not in threat list
            return False, 0, True   # found=True means GSB was consulted successfully

        return False, 0, False  # API error — fall through to Layer 3

    except Exception:
        return False, 0, False  # Network error — fall through to Layer 3



# LAYER 2C — MalwareBazaar (for File Hashes)
def check_malwarebazaar_reputation(file_hash):
    """
    Queries abuse.ch's MalwareBazaar API to check a file hash reputation.

    WHY MALWAREBAZAAR INSTEAD OF VIRUSTOTAL FOR HASHES:
    MalwareBazaar is specifically curated for malware that spreads via email
    — banking trojans (Emotet, Trickbot), ransomware droppers, macro-enabled
    Office documents, and credential stealers. This is precisely the malware
    PhishGuard is designed to detect in email attachments.

    Unlike VirusTotal, MalwareBazaar has:
    - No per-minute rate limit
    - Free Auth-Key (obtained at https://auth.abuse.ch/)
    - Richer metadata (malware family name, tags, file type)

    Per the official MalwareBazaar API documentation (https://bazaar.abuse.ch/api/),
    every request MUST include the HTTP header "Auth-Key" with the registered key.
    Without it the API returns query_status: "no_api_key".

    API Endpoint : POST https://mb-api.abuse.ch/api/v1/
    Auth Header  : Auth-Key: <MALWAREBAZAAR_API_KEY>
    Docs         : https://bazaar.abuse.ch/api/

    Response "query_status":
        "ok"             → hash found in MalwareBazaar (malicious)
        "hash_not_found" → hash not in database (unknown, fall to VT)
        "no_api_key"     → Auth-Key header missing or invalid
        "illegal_hash"   → malformed hash string

    Args:
        file_hash (str): SHA-256 or MD5 hash of the email attachment

    Returns:
        tuple: (is_malicious: bool, score: int, found: bool)
            found=True  → MalwareBazaar has a record for this hash
            found=False → not in database, proceed to Layer 3
    """
    if not MALWAREBAZAAR_API_KEY:
        return False, 0, False

    api_url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY}      # Required per official docs
    data    = {"query": "get_info", "hash": file_hash}

    try:
        response = requests.post(api_url, headers=headers, data=data, timeout=10)

        if response.status_code == 200:
            result       = response.json()
            query_status = result.get("query_status", "")

            if query_status == "ok":
                # Hash confirmed in MalwareBazaar
                malware_info = result.get("data", [{}])[0]
                family       = malware_info.get("signature", "Unknown Family")
                print(f"[MalwareBazaar HIT] Hash: {file_hash} — Family: {family}")
                return True, 100, True

            elif query_status == "hash_not_found":
                # Not in MalwareBazaar — fall through to VirusTotal
                return False, 0, False

            elif query_status == "no_api_key":
                # Auth-Key was rejected — log and fall through
                print("[MalwareBazaar] Auth-Key missing or invalid.")
                return False, 0, False

        return False, 0, False

    except Exception:
        return False, 0, False

def check_urlhaus_reputation(url_string):
    """
    Queries the URLhaus API to check if a URL is distributing malware.
    Uses the same abuse.ch API key as MalwareBazaar.
    """
    if not MALWAREBAZAAR_API_KEY:  # URLHaus and malwarebazar are operated by same organization so they provide common API key.
        return False, 0, False

    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY}
    data = {"url": url_string}

    try:
        response = requests.post(api_url, headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            query_status = result.get("query_status")

            if query_status == "ok":
                # URL is listed in URLhaus as active malware host
                url_status = result.get("url_status")
                if url_status == "online":
                    print(f"[URLhaus HIT] {url_string} is ONLINE distributing malware!")
                    return True, 100, True
                else:
                    print(f"[URLhaus HIT] {url_string} is listed (offline).")
                    return True, 50, True  # lower score if offline

            elif query_status == "no_api_key":
                print("[URLhaus] Key error.")
                return False, 0, False

        return False, 0, True  # Consulted but not found
    except Exception:
        return False, 0, False  # Network error


# LAYER 3 — VirusTotal (Last Option for mapping)
# Called ONLY when Layers 1 and 2 both returned nothing.
# Rate limit applies here but is rarely reached in practice.
# IPs are NOT re-checked here — AbuseIPDB is their final source.
def check_virustotal_url(url_string):
    """
    Queries VirusTotal for a URL not found in Google Safe Browsing.
    Last resort with 70+ AV engines for broadest coverage.
    Rate Limit: 4 requests/minute on free plan.
    """
    if not VIRUSTOTAL_API_KEY:
        return False, 0

    url_id  = base64.urlsafe_b64encode(url_string.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 429:
            print("[VT] Rate limit hit. Waiting 30 seconds...")
            time.sleep(30)
            response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data            = response.json()
            stats           = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            return (malicious_count >= 2), malicious_count

        return False, 0
    except Exception:
        return False, 0


def check_virustotal_domain(domain_string):
    """
    Queries VirusTotal for a domain not found in Google Safe Browsing.
    Last resort with 70+ AV engines for broadest coverage.
    Rate Limit: 4 requests/minute on free plan.
    """
    if not VIRUSTOTAL_API_KEY:
        return False, 0

    api_url = f"https://www.virustotal.com/api/v3/domains/{domain_string}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 429:
            print("[VT] Rate limit hit. Waiting 30 seconds...")
            time.sleep(30)
            response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data            = response.json()
            stats           = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            return (malicious_count >= 2), malicious_count

        return False, 0
    except Exception:
        return False, 0


def check_virustotal_hash(file_hash):
    """
    Queries VirusTotal for a file hash not found in MalwareBazaar.
    Last resort with 70+ AV engines for broadest coverage.
    Rate Limit: 4 requests/minute on free plan.
    """
    if not VIRUSTOTAL_API_KEY:
        return False, 0

    api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 429:
            print("[VT] Rate limit hit. Waiting 30 seconds...")
            time.sleep(30)
            response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data            = response.json()
            stats           = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            return (malicious_count >= 2), malicious_count

        return False, 0
    except Exception:
        return False, 0


# ORCHESTRATOR — Only function called from outside this file

def update_email_iocs(email_record):
    """
    Main entry point for the threat intelligence scanning pipeline.

    Called from analyze_email.py after IOCs have been extracted and saved:
        iocs      = extract_iocs(parsed_data)
        save_iocs(iocs, email_record)
        ioc_score = update_email_iocs(email_record)   <- this function

    Loops through every IOC linked to the email and resolves each one
    through the three-layer strategy. A result from any layer short-circuits
    the remaining layers for that IOC.

    Args:
        email_record: Django EmailRecord model instance

    Returns:
        int: 35 if any malicious IOC found, 0 otherwise
    """
    iocs = IOC.objects.filter(email_ids__contains=str(email_record.id))

    if not iocs.exists():
        return 0

    has_malicious_ioc = False

    for ioc in iocs:

        # Already resolved from a previous pipeline run — read result and skip
        if ioc.is_scanned:
            if ioc.is_malicious:
                has_malicious_ioc = True
            continue

        is_malicious = False
        score        = 0
        resolved     = False

        # LAYER 1: Database Cache
        cached_malicious, cached_score, found_in_cache = get_cached_ioc_result(
            ioc.ioc_type, ioc.value
        )
        if found_in_cache:
            print(f"[CACHE HIT] {ioc.ioc_type}: {ioc.value}")
            is_malicious = cached_malicious
            score = cached_score
            resolved = True

        #  LAYER 2: Specialized APIs
        if not resolved:

            if ioc.ioc_type == "ip":
                # IPs → AbuseIPDB (final source for IPs, no Layer 3 fallback)
                print(f"[AbuseIPDB] Checking IP: {ioc.value}")
                is_malicious, score = check_ip_reputation(ioc.value)
                resolved = True


            elif ioc.ioc_type in ("url", "domain"):
                # 1. First check Google Safe Browsing
                print(f"[GSB] Checking {ioc.ioc_type}: {ioc.value}")
                gsb_malicious, gsb_score, gsb_found = check_gsb_reputation(ioc.value)
                if gsb_found and gsb_malicious:
                    is_malicious = gsb_malicious
                    score = gsb_score
                    resolved = True
                # 2. If GSB didn't find anything, fallback to URLhaus (NEW)
                if not resolved and ioc.ioc_type == "url":
                    print(f"[URLhaus] Checking URL: {ioc.value}")
                    uh_malicious, uh_score, uh_found = check_urlhaus_reputation(ioc.value)
                    if uh_found and uh_malicious:
                        is_malicious = uh_malicious
                        score = uh_score
                        resolved = True

            # gsb_found=False → network error or API issue → fall to Layer 3
            elif ioc.ioc_type == "hash":
                # Hashes → MalwareBazaar (email malware focused, unlimited)
                print(f"[MalwareBazaar] Checking hash: {ioc.value}")
                mb_malicious, mb_score, mb_found = check_malwarebazaar_reputation(ioc.value)
                if mb_found:
                    is_malicious = mb_malicious
                    score = mb_score
                    resolved = True
                # mb_found=False → hash unknown → fall to Layer 3

        #  LAYER 3: VirusTotal (Last fallback layer)
        # Only for URLs, Domains, Hashes that missed Layer 2.
        # IPs are not re-checked — AbuseIPDB is their final source.
        if not resolved:

                if ioc.ioc_type == "url":
                    print(f"[VT fallback] URL: {ioc.value}")
                    is_malicious, score = check_virustotal_url(ioc.value)
                    time.sleep(15)

                elif ioc.ioc_type == "domain":
                    print(f"[VT fallback] Domain: {ioc.value}")
                    is_malicious, score = check_virustotal_domain(ioc.value)
                    time.sleep(15)

                elif ioc.ioc_type == "hash":
                    print(f"[VT fallback] Hash: {ioc.value}")
                    is_malicious, score = check_virustotal_hash(ioc.value)
                    time.sleep(15)

        #  Persist Result
        ioc.is_malicious = is_malicious
        ioc.threat_score = score
        ioc.is_scanned = True
        ioc.save()

        if ioc.is_malicious:
           has_malicious_ioc = True

    if has_malicious_ioc:
        return 35
    return 0