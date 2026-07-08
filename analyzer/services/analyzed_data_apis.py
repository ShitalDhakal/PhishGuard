import json
from django.db.models import Q
from django.http import JsonResponse
from Mailbox.models import EmailRecord
from Mailbox.services.user_data import get_email_with_ioc
from accounts.models import User
from analyzer.models import IOC, AnalysisReport
from analyzer.services.risk_scorer import determine_verdict



def get_email_data_and_scores(request):
    try:
        data = {}
        if request.body:
            data = json.loads(request.body)
        email_list = []
        user_id = data.get("user_id")
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