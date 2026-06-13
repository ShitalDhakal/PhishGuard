import os
import time  # Use for VirusTotal, Waits for 15 seconds, to avoid rate limiting
import base64  # URLs to be Base64 URL-safe encoded before querying them
import requests
from analyzer.models import IOC

# Load API keys from environment
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

