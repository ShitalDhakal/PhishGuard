import os
import time  # Use for VirusTotal, Waits for 15 seconds, to avoid rate limiting
import base64  # URLs to be Base64 URL-safe encoded before querying them
import requests
from analyzer.models import IOC

# Load API keys from environment
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_ip_reputation(ip_address):
    """
    Queries AbuseIPDB API for IP reputation.
    Returns (is_malicious: bool, score: int)

    Example: (True, 85)
    """
    if not ABUSEIPDB_API_KEY:
        # Default to safe if API key is not configured
        return False, 0

    url = "https://api.abuseipdb.com/api/v2/check" # AbuseIPDB API URL where the request will be sent.
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,  # IP address we provided  to check
        "maxAgeInDays": "90" # Only consider abuse reports from the last 90 days.
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10) # sends a GET request to AbuseIPDB.
        # Convert JSON response into a Python dictionary
        if response.status_code == 200:
            data = response.json()
            # Safely retrieve the abuse confidence score from the API response, defaulting to 0 if the field is missing.
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            # Threshold: 25% or higher confidence score is considered malicious
            return (score >= 25), score
        return False, 0
    except Exception:
        return False, 0


def check_url_reputation(url_string):
    """
    Queries VirusTotal API for URL reputation.
    Returns (is_malicious: bool, score: int)

    Eg : (True, 5)
    """
    if not VIRUSTOTAL_API_KEY:
        return False, 0

    # Base64 urlsafe encode the URL and strip '=' padding for VirusTotal
    # VirusTotal expects the URL to be URL-safe Base64 encoded when querying the /urls/{id} endpoint.

    # Convert url to base64 encoded format: b'aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2dpbg==' and then Convert bytes back to a string removing = sing
    url_id = base64.urlsafe_b64encode(url_string.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        # Send the request
        response = requests.get(api_url, headers=headers, timeout=10)

        # Handle Rate Limit (HTTP 429)
        if response.status_code == 429:
            time.sleep(30)  # Wait 30 seconds and retry
            response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json() # convert json response to python dictonary
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            # Threshold: 2 or more vendors flagging it is considered malicious
            return (malicious_count >= 2), malicious_count
        return False, 0
    except Exception:
        return False, 0


def check_domain_reputation(domain_string):
    """
    Queries VirusTotal API for Domain reputation.
    Returns (is_malicious: bool, score: int)
    """
    if not VIRUSTOTAL_API_KEY:
        return False, 0

    api_url = f"https://www.virustotal.com/api/v3/domains/{domain_string}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 429:
            time.sleep(30)
            response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            return (malicious_count >= 2), malicious_count
        return False, 0
    except Exception:
        return False, 0


def check_file_hash_reputation(file_hash):
    """
    Queries VirusTotal API for a file hash (SHA-256/MD5).
    Returns (is_malicious: bool, score: int)
    """
    if not VIRUSTOTAL_API_KEY:
        return False, 0

    api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 429:
            time.sleep(30)
            response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            # Threshold: 2 or more vendors flagging it is considered malicious
            return (malicious_count >= 2), malicious_count
        return False, 0
    except Exception:
        return False, 0


def update_email_iocs(email_record):
    """
    Orchestrator for threat intel. Looks up every IOC associated with the email.
    Saves reputation data, handles VT API rate limits, and computes the total ioc_score.

    Returns: ioc_score (integer from 0 to 35)
    """
    # Fetch all IOC records linked to this email
    # When Django runs IOC.objects.filter(...), it pulls all rows from the database and turns them into a list of Python objects in memory
    # Search the 'email_ids' text column to find all IOCs associated with this email's ID.
    iocs = IOC.objects.filter(email_ids__contains=str(email_record.id))

    if not iocs.exists():
        return 0

    has_malicious_ioc = False

    for ioc in iocs:
        # Only query API if the IOC hasn't been checked yet
        if ioc.is_scanned is False:
            is_malicious = False
            score = 0

            if ioc.ioc_type == "ip":
                print("Checking IP Reputation...")
                is_malicious, score = check_ip_reputation(ioc.value)

            elif ioc.ioc_type == "url":
                print("Checking URL Reputation...")
                is_malicious, score = check_url_reputation(ioc.value)
                time.sleep(15)  # Enforce rate limit sleep for VirusTotal (4 req/min)

            elif ioc.ioc_type == "domain":
                print("Checking Domain Reputation...")
                is_malicious, score = check_domain_reputation(ioc.value)
                time.sleep(15)  # Enforce rate limit sleep for VirusTotal (4 req/min)

            elif ioc.ioc_type == "hash":
                print("Checking File Hash Reputation...")
                is_malicious, score = check_file_hash_reputation(ioc.value)
                time.sleep(15)  # Enforce rate limit sleep for VirusTotal (4 req/min)

            # Save the results to database
            ioc.is_malicious = is_malicious
            ioc.threat_score = score
            ioc.save()

        # If any IOC is malicious, flag this email as having malicious IOCs
        if ioc.is_malicious:
            has_malicious_ioc = True

    # Calculate IOC score (Step 12: Weight is max 35 points if malicious IOC found)
    if has_malicious_ioc:
        return 35
    return 0