import logging

import json

from django.http import JsonResponse
from Mailbox.models import EmailRecord
from Mailbox.services.imap_fetcher import fetch_emails
from Mailbox.services.user_data import load_ioc
from analyzer.models import AnalysisReport
from analyzer.services.email_parser    import parse_email
from analyzer.services.header_analyzer import analyze_headers
from analyzer.services.ioc_extractor import extract_iocs, save_iocs
from analyzer.services.keyword_detector import detect_keywords
from analyzer.services.threat_intel    import update_email_iocs
from analyzer.services.ml_classifier   import classify
from analyzer.services.risk_scorer     import analyze_threat_risk


logger = logging.getLogger(__name__)

def analyze_email(request):

    fetch_emails(request)
    data = {}
    if request.body:
        data = json.loads(request.body)


    unscanned_emails = []
    if(data.get("email")):
        unscanned_emails = list(EmailRecord.objects.filter(recipient__icontains=data.get("email"), scanned=False))

    else:
        unscanned_emails = list(EmailRecord.objects.filter(scanned=False))


    for email_record in unscanned_emails:
        parsed_data = parse_email(email_record)
        try:
            print("Analyzing headers...")
            auth_data = analyze_headers(parsed_data)
            logger.debug("Step 2 complete: auth_score=%d", auth_data.get("auth_score", 0))
        except Exception as e:
            logger.error("Step 2 FAILED (analyze_headers): %s", e)
            auth_data = {"auth_score": 0, "findings": {}}


        try:
            print("Extracting IOCs...")
            load_ioc(parsed_data)
        except Exception as e:
            logger.error("Step 3 FAILED (save_iocs): %s", e)



    #  Step 4: Keyword Detection
    # Scans subject + body for phishing keyword categories.
    # Returns keyword_score (0–15) and matched evidence.
        try:
            print("Detecting keywords...")
            subject   = parsed_data.get("subject", "") or ""
            body_text = parsed_data.get("body_text", "") or ""
            keyword_data = detect_keywords(subject, body_text)
            logger.debug("Step 4 complete: keyword_score=%d", keyword_data.get("keyword_score", 0))
        except Exception as e:
            logger.error("Step 4 FAILED (detect_keywords): %s", e)
            keyword_data = {"keyword_score": 0, "matched_keywords": [], "categories_found": []}

   #  Step 5: Threat Intelligence
    # Queries VirusTotal and AbuseIPDB for each IOC saved in Step 3.
    # Returns ioc_score: 35 if any IOC is malicious, 0 if all clean.
    # Note: This step can take 15–60 seconds due to API rate limits.
        try:
            print("Updating email IOCs...")
            ioc_score = update_email_iocs(email_record)
            logger.debug("Step 5 complete: ioc_score=%d", ioc_score)
        except Exception as e:
            logger.error("Step 5 FAILED (update_email_iocs): %s", e)
            ioc_score = 0

# Step 6: ML Classification
    # Classifies the email body using the trained MultinomialNB model.
    # Returns ml_score (0–100) — phishing probability percentage.
        try:
            print("Analyzing body text...")
            ml_score = classify(body_text)
            logger.debug("Step 6 complete: ml_score=%d", ml_score)
        except Exception as e:
            logger.error("Step 6 FAILED (classify): %s", e)
            ml_score = 0


     #Step 7: Risk Scoring
    # Combines all four scores into a final risk_score (0–100),
    # assigns a verdict (SAFE / SUSPICIOUS / MALICIOUS),
    # and determines the phishing sub-category.
        try:
            print("Calculating final risk score...")
            risk_result = analyze_threat_risk(auth_data, keyword_data, ioc_score, ml_score)
            logger.info(
                "Step 7 complete: score=%d verdict=%s type=%s",
                risk_result["risk_score"], risk_result["verdict"], risk_result.get("phishing_type")
            )
        except Exception as e:
            logger.error("Step 7 FAILED (analyze_threat_risk): %s", e)
            risk_result = {
                "risk_score": 0, "verdict": "Safe",
                "classification": "Clean", "phishing_type": None
            }



    #  Step 8: Save to AnalysisReport
    # update_or_create() instead of create()
    # create() always inserts a brand new row. If this email was already
    # analyzed before (e.g. APIs were down and we re-run the analysis),
    # create() would raise an IntegrityError because email_id is unique -
    # we cannot have two AnalysisReport rows for the same email.
    #
    # update_or_create() solves this by doing the following in one query:
    #   1. Look for an existing AnalysisReport row where email_id = email_record
    #   2. If found   → UPDATE that row with the new values from defaults={}
    #   3. If not found → CREATE a new row using both email_id and defaults={}
    #
        print("Saving analysis report...")
        report, created = AnalysisReport.objects.update_or_create(
            # This is the LOOKUP FIELD. Django uses this to search: "Does a report for this email exist?"
            email_id=email_record,
            defaults={
                # Final weighted risk score (0–100) from risk_scorer.py
                # Combines auth + ioc + keyword + ml using the dual-formula system
                "overall_risk_score": risk_result["risk_score"],

                # Security verdict assigned by determine_verdict() in risk_scorer.py
                # Possible values: "Safe", "Suspicious", "Malicious"
                "verdict": risk_result["verdict"],

                # Broad threat category assigned by determine_classification()
                # Possible values: "Clean", "Spam", "Phishing"
                "classification": risk_result["classification"],

                # Phishing sub-category — more specific than classification.
                # .get() is used instead of [] because phishing_type is None
                # for Clean and Spam emails (no sub-category applies).
                "phising_type": risk_result.get("phishing_type"),


                # Score from header_analyzer.py (0–30)
                # Measures SPF/DKIM/DMARC failures, Reply-To mismatch, etc.
                # .get("auth_score", 0) → returns 0 if analyze_headers() failed
                "authentication_risk_score": auth_data.get("auth_score", 0),

                # Score from threat_intel.py: 35 if any IOC (URL/IP/domain)
                # was confirmed malicious by VirusTotal or AbuseIPDB, else 0
                "ioc_risk_score": ioc_score,

                # Raw probability score from ml_classifier.py (0–100)
                # Represents how phishing-like the email text is to the ML model
                "ml_risk_score": ml_score,
            }
        )
        # Check if the report was created fresh or just updated
        if created:
            action = "created"
        else:
            action = "updated"

        #  Mark the EmailRecord as scanned

        #   scanned = True
        #       Tells the IMAP fetcher that this email has already been fully analyzed.
        #       Without this flag, every time the fetcher runs, it would re-queue
        #       already-analyzed emails and waste time + API quota.
        email_record.scanned = True

        #  Copies the final risk score onto the EmailRecord itself.
        email_record.score = risk_result["risk_score"]

        #       Tells Django to only write these two columns to the database.
        #       Without update_fields, Django would UPDATE all 20+ columns of Mailbox/models.py
        email_record.save(update_fields=["scanned", "score"])
    
    return JsonResponse({"message": "Email scanned.", "status": 200}, safe=False)
