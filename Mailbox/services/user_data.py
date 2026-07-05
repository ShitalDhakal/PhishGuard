import email
import json
from django.http import HttpResponse, JsonResponse

from analyzer.models import IOC
from Mailbox.models import EmailRecord
from analyzer.services.email_parser import parse_email
from analyzer.services.ioc_extractor import extract_iocs, save_iocs
from django.db.models import Q

def fetch_ioc(request):
    try:
        data = {}
        if request.body:
            data = json.loads(request.body)
        
        load_ioc(request)
        
        if data.get('email'):
            ioc_list = list(IOC.objects.filter(email=data.get('email')).values())
        else:
            if(request.session.get('login_user_role') != 'analyst'):
                return JsonResponse({"message": "Only analyst can fetch all IOCs!", "status": 405}, safe=False)
            ioc_list = list(IOC.objects.all().values())
            
        return JsonResponse({"data": ioc_list, "status": 200}, safe=False)
    except Exception as e:
        print(f"Error in fetch_ioc: {e}")
        return HttpResponse(status=500)
    

def load_ioc(parsed_email):
    try:
        email_with_iocs = []
        email_with_iocs.append({
            "email": parsed_email, 
            "iocs": extract_iocs(parsed_email)
        })

        for item in email_with_iocs:
            email_record = item.get("email")
            iocs = item.get("iocs")
            save_iocs(email_record, iocs)

        return JsonResponse({"message": "IOCs loaded successfully.", "status": 200})
    except Exception as e:
        print(f"Error in load_ioc: {e}")
        return HttpResponse(status=500)
    
def get_ioc_overview(request):
    try:
        data = {}
        if(request.body):
            data = json.loads(request.body)

        email_ids = []
        ioc_list = []

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

        iocs = list(IOC.objects.filter(email_ids__in=email_ids).values())
        for ioc in iocs:
            email_id_array = [int(num) for num in ioc['email_ids'].split(",")]
            if any(email_id in email_ids for email_id in email_id_array):
                ioc_list.append(ioc)
        


        return JsonResponse({"data": ioc_list, "status": 200}, safe=False)
    except Exception as e:
        print(f"Error in get_overview: {e}")
        return HttpResponse(status=500)
    
def get_email_overview(request):
    try:
        data = {}
        email_content = []
        email_list = []
        if(request.body):
            data = json.loads(request.body)


        if(data.get('email')):
            email_list = list(EmailRecord.objects.filter(recipient__icontains=data.get('email'), scanned=True).values())

        else:
            if(request.session.get('login_user_role') != 'analyst'):
                return JsonResponse({"message": "Only analyst can fetch overview!", "status": 405}, safe=False)
            email_list = list(EmailRecord.objects.filter(scanned=True).values())

        
        for individual_email in email_list:
            content = get_email_with_ioc(individual_email)
            email_content.append(content)

        return JsonResponse({"data": email_content, "status": 200}, safe=False)
    
    except Exception as e:
        print(e)
        return JsonResponse({"message":"Error", "status": 500})

def get_email_with_ioc(email_data):
    try:

        ioc = list(IOC.objects.filter(
            Q(email_ids__startswith=f"{email_data.get("id")}, ")
            | Q(email_ids__endswith=f",{email_data.get("id")}")
            | Q(email_ids__contains=f", {email_data.get("id")},")
            | Q(email_ids__exact=f"{email_data.get("id")}")
        ).values())

        content = {
            "message_id": email_data.get("message_id"),
            "sender"   : email_data.get("sender"),
            "recipient": email_data.get("recipient"),
            "subject"  : email_data.get("subject"),
            "date"   : email_data.get("date"),
            "body" : email_data.get("body_html"),
            "iocs" : ioc
        }
    except Exception as e:
        print(e)
        return {}

    return content
        
