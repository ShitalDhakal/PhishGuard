import json
from django.http import HttpResponse, JsonResponse

from analyzer.models import IOC
from Mailbox.models import EmailRecord
from analyzer.services.email_parser import parse_email
from analyzer.services.ioc_extractor import extract_iocs, save_iocs


def fetch_ioc(request):
    try:
        data = {}
        if request.body:
            data = json.loads(request.body)
        
        load_ioc(request)
        
        if data.get('email'):
            ioc_list = list(IOC.objects.filter(email=data.get('email')).values())
        else:
            ioc_list = list(IOC.objects.all().values())
            
        return JsonResponse(ioc_list, safe=False)
    except Exception as e:
        print(f"Error in fetch_ioc: {e}")
        return HttpResponse(status=500)
    

def load_ioc(request):
    try:
        unscanned_queryset = EmailRecord.objects.filter(scanned=False)
        emails = list(unscanned_queryset)
        
        if not emails:
            return JsonResponse({"message": "No new emails to process.", "status": 200})

        email_with_iocs = []
        for email in emails:
            parsed_email = parse_email(email)
            email_with_iocs.append({
                "email": parsed_email, 
                "iocs": extract_iocs(parsed_email)
            })

        for item in email_with_iocs:
            email_record = item.get("email")
            iocs = item.get("iocs")
            save_iocs(email_record, iocs)

        unscanned_queryset.update(scanned=True)
        
        return JsonResponse({"message": "IOCs loaded successfully.", "status": 200})
    except Exception as e:
        print(f"Error in load_ioc: {e}")
        return HttpResponse(status=500)