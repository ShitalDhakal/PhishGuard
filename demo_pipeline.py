import os
import sys
import django

# Setup Django environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PhishGuard.settings")
django.setup()

from Mailbox.models import EmailRecord
from analyzer.models import IOC
from analyzer.services.email_parser import parse_email
from analyzer.services.ioc_extractor import extract_iocs, save_iocs
from analyzer.services.threat_intel import update_email_iocs

def run_demo():
    print("=" * 65)
    print("              PHISHGUARD MID-TERM PIPELINE DEMO")
    print("=" * 65)
    
    # 1. Fetch latest email from DB
    email = EmailRecord.objects.first()
    if not email:
        print("[-] No emails found in the database. Please run imap_fetcher.py first.")
        return
        
    print(f"[+] Loaded Email ID: {email.id}")
    print(f"[+] Subject: {email.subject}")
    print(f"[+] Sender: {email.sender}")
    print(f"[+] Date: {email.date}")
    print("-" * 65)
    
    # 2. Step 6: Parse email
    print("[*] Process 1: Parsing email structure (Step 6)...")
    parsed_data = parse_email(email)
    print(f"    - Found {parsed_data.get('url_count', 0)} URLs")
    print(f"    - Has attachments: {parsed_data.get('has_attachments')}")
    print(f"    - Display-name spoofing detected: {parsed_data.get('display_name_mismatch')}")
    print("-" * 65)
    
    # 3. Step 8: Extract IOCs
    print("[*] Process 2: Extracting Indicators of Compromise (Step 8)...")
    iocs = extract_iocs(parsed_data)
    save_iocs(email, iocs)
    print(f"    - Extracted and saved {len(iocs)} unique IOCs")
    for i in iocs:
        print(f"      * [{i['type'].upper()}] {i['value']} (Source: {i['source']})")
    print("-" * 65)
    
    # 4. Step 10: Threat Intel Check
    print("[*] Process 3: Running Threat Intelligence Lookups (Step 10)...")
    print("    (Note: Sleeping 15s between scans to respect API rate limits)")
    score = update_email_iocs(email)
    print(f"[+] Analysis Complete! IOC Score: {score}/35")
    print("-" * 65)
    
    # 5. Display Database Scan Results
    print("=== FINAL POSTGRESQL DATABASE RECORD ===")
    saved_iocs = IOC.objects.filter(email_record=email)
    for ioc in saved_iocs:
        print(f"[{ioc.ioc_type.upper()}] {ioc.value}")
        print(f"  ├─ Source: {ioc.source}")
        print(f"  ├─ Malicious: {ioc.is_malicious}")
        print(f"  └─ Score/Detections: {ioc.threat_score}")
    print("=" * 65)

if __name__ == "__main__":
    run_demo()
