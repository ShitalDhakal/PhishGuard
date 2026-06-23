import json
from django.http import HttpResponse, JsonResponse

from analyzer.models import IOC
from Mailbox.models import EmailRecord
from analyzer.services.email_parser import parse_email
from analyzer.services.ioc_extractor import extract_iocs, save_iocs

async def fetch_ioc(request):
    try:
        data = {}
        if(request.body):
            data = json.loads(request.body)\
        
        ioc_list = []
        await load_ioc(request)
        if(data.get('email')):
            ioc_list = IOC.objects.filter(email=data['email']).values()
        else:
            ioc_list = IOC.objects.all().values()
        return JsonResponse(list(ioc_list), safe=False)
    except Exception as e:
        print(f"Error: {e}")
        return HttpResponse(500)
    
async def load_ioc(request):
    try:
        emails = list(EmailRecord.objects.filter(scanned=False).values())
        email_with_iocs = []
        for email in emails:
            parsed_email = parse_email(email)
            email_with_iocs.append({"email":parsed_email, "iocs":extract_iocs(parsed_email)})

        for email in email_with_iocs:
            email_record = email.get("email")
            iocs = email.get("iocs")
            save_iocs(email_record, iocs)

        EmailRecord.objects.update(scanned=True)
        return JsonResponse({"message":"IOCs loaded successfully.", "status": 200})
    except Exception as e:
        print(f"Error: {e}")
        return HttpResponse(500)