import json
from unittest import case
from django.db.models import Q
from django.http import JsonResponse
from Mailbox.models import EmailRecord
from Mailbox.services.user_data import get_email_with_ioc
from accounts.models import User
from analyzer.models import IOC, AnalysisReport
from analyzer.services.risk_scorer import determine_verdict
from Mailbox.services.user_data import get_email_with_ioc, get_recurring_iocs

def get_email_data_and_scores(request):
    try:
        data = {}
        if request.body:
            data = json.loads(request.body)
        email_list = []
        user_id = data.get("user_id")
        verdict = data.get("verdict")
        sender_email = data.get("sender_email")
        date_from = data.get("date_from")
        date_to = data.get("date_to")
        if(user_id > 0):
            user = User.objects.get(user_id=user_id)
            email_list = list(EmailRecord.objects.filter(recipient__icontains=user.email, scanned=True).values("id", "sender", "recipient", "subject", "date", "body_html", "source_folder"))
        else:
            if(request.session.get('login_user_role') != 'analyst'):
                return JsonResponse({"message": "Only analyst can fetch all emails!", "status": 405}, safe=False)
            email_list = list(EmailRecord.objects.filter(scanned=True).values("id", "sender", "recipient", "subject", "date", "body_html", "source_folder"))

        analyzed_data_list = []

        for email_record in email_list:
            analyzed_data = list(AnalysisReport.objects.filter(email_id_id=email_record.get("id")).values())

            iocs = get_email_with_ioc(email_record, only_iocs=True)
            data = {
                "email_data": email_record,
                "analyzed_data": analyzed_data,
                "iocs": iocs
            }
            analyzed_data_list.append(data)

        return JsonResponse({"data": analyzed_data_list, "status": 200}, safe=False)
    except Exception as e:
        print(f"Error in get_email_data_and_scores: {e}")
        return JsonResponse({"message": "Server error", "status": 500}, safe=False)


def update_risk_score(request):
    try:
        data = {}

        if(request.session.get('login_user_role') != 'analyst'):
            return JsonResponse({"message": "Only analyst can update risk score!", "status": 405}, safe=False)
        if request.body:
            data = json.loads(request.body)
            email_id = data.get("email_id")
            risk_score = data.get("risk_score")
            if not email_id:
                return JsonResponse({"message": "Email ID is required", "status": 400}, safe=False)


            # Update the risk score in the AnalysisReport
            analysis_report = AnalysisReport.objects.get(email_id_id=email_id)
            analysis_report.overall_risk_score = risk_score
            analysis_report.verdict = determine_verdict(risk_score)
            analysis_report.save()

            return JsonResponse({"message": "Risk score updated successfully", "risk_score": risk_score, "status": 200}, safe=False)
    except Exception as e:
        print(f"Error in update_risk_score: {e}")
        return JsonResponse({"message": "Server error", "status": 500}, safe=False)
    

def dashboard_data(request):
    try:
        data = {}
        if request.body:
            data = json.loads(request.body)
        email_ids = []
        if(data.get('email')):
            emails = EmailRecord.objects.filter(recipient__icontains=data.get('email'), scanned=True)
            for email in emails:
                email_ids.append(email.id)
        else:
            if(request.session.get('login_user_role') != 'analyst'):
                return JsonResponse({"message": "Only analyst can fetch overview!", "status": 405}, safe=False)
            emails = EmailRecord.objects.filter(scanned=True)
            for email in emails:
                email_ids.append(email.id)
        
        verdict_count = {
            "Safe": 0,
            "Suspicious": 0,
            "Malicious": 0,
            "Unknown": 0
        }

        avg_risk_scores = {
            "Overall": 0,
            "IOC": 0,
            "Text": 0,
            "Authentication": 0
        }

        phishing_type_count = {
            "General Spam": 0,
            "Banking Fraud": 0,
            "Reward Scam": 0,
            "Fake Invoice": 0,
            "Account Suspension": 0,
            "Credential Harvesting": 0,
            "Delivery Scam": 0,
            "None": 0
        }

        malicious_sender_count = {

        }

        malicious_email_count = 0
        no_notes_count = 0
        verdict_data = list(AnalysisReport.objects.filter(email_id_id__in=email_ids).values())
        for report in verdict_data:
            match(report.get("verdict").lower()):
                case "safe":
                    verdict_count["Safe"] += 1
                case "suspicious":
                    verdict_count["Suspicious"] += 1
                case "malicious":
                    verdict_count["Malicious"] += 1
                case _:
                    verdict_count["Unknown"] += 1

            avg_risk_scores["Overall"] += report.get("overall_risk_score", 0)
            avg_risk_scores["IOC"] += report.get("ioc_risk_score", 0)
            avg_risk_scores["Text"] += report.get("ml_risk_score", 0)
            avg_risk_scores["Authentication"] += report.get("authentication_risk_score", 0)

            phishing_type = report.get("phising_type") or ""
            
            match(phishing_type.lower()):
                case "general spam":
                    phishing_type_count["General Spam"] += 1
                case "banking fraud":
                    phishing_type_count["Banking Fraud"] += 1
                case "reward scam":
                    phishing_type_count["Reward Scam"] += 1
                case "fake invoice":
                    phishing_type_count["Fake Invoice"] += 1
                case "account suspension":
                    phishing_type_count["Account Suspension"] += 1  
                case "credential harvesting":
                    phishing_type_count["Credential Harvesting"] += 1
                case "delivery scam":
                    phishing_type_count["Delivery Scam"] += 1
                case _:
                    phishing_type_count["None"] += 1
                
            if(report.get("verdict").lower() == "malicious"):
                malicious_email_count += 1

            if(report.get("notes") or "" == ""):
                no_notes_count += 1

            if(report.get("verdict").lower() in ["malicious", "suspicious"]):
                email = EmailRecord.objects.get(id=report.get("email_id_id"))
                sender = email.sender.replace("<", "(").replace(">", ")")
                if(sender in malicious_sender_count):
                    malicious_sender_count[sender] += 1
                else:
                    malicious_sender_count[sender] = 1



        avg_risk_scores["Overall"] = avg_risk_scores["Overall"] / len(verdict_data)
        avg_risk_scores["IOC"] = avg_risk_scores["IOC"] / len(verdict_data)
        avg_risk_scores["Text"] = avg_risk_scores["Text"] / len(verdict_data)
        avg_risk_scores["Authentication"] = avg_risk_scores["Authentication"] / len(verdict_data)

        malicious_emails =list(IOC.objects.filter(is_malicious=True, email_ids__in=email_ids).values())

        recurring_iocs = []

        for email_id in email_ids:
            recurring_iocs.append(get_recurring_iocs(email_id))

        return JsonResponse({"verdict_count": verdict_count, "email_count": len(email_ids), "malicious_email_count": len(malicious_emails), "status": 200, "avg_risk_scores": avg_risk_scores, "phishing_type_count": phishing_type_count, "no_notes_count": no_notes_count, "malicious_sender_count": dict(sorted(malicious_sender_count.items(), key=lambda x: x[1], reverse=True)), "recurring_iocs": recurring_iocs, "status": 200}, safe=False)
    except Exception as e:
        print(f"Error in dashboard_data: {e}")
        return JsonResponse({"message": "Server error", "status": 500}, safe=False)
