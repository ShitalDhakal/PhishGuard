import json
from django.db.models import Q
from django.http import JsonResponse
from Mailbox.models import EmailRecord
from Mailbox.services.user_data import get_email_with_ioc
from analyzer.models import IOC, AnalysisReport



def get_email_data_and_scores(request):
    try:
        data = {}
        if request.body:
            data = json.loads(request.body)
        email_list = []
        if(data.get("email")):
            email_list = list(EmailRecord.objects.filter(recipient__icontains=data.get("email"), scanned=True).values("id", "sender", "recipient", "subject", "date", "body_html", "source_folder"))
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


