import os
import time  # Use for VirusTotal, Waits for 15 seconds, to avoid rate limiting
import base64  # URLs to be Base64 URL-safe encoded before querying them
import requests
from analyzer.models import IOC

# Load API keys from environment
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
VIRUSTOTAL_API_KEY           = os.getenv("VIRUSTOTAL_API_KEY")

# MalwareBazaar requires NO API key it is a fully open public API.

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

    return False, 0, False