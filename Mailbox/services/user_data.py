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
        
        load_ioc_all(request)
        
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
    
def load_ioc_all(request):
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
        


        return JsonResponse({"data": ioc_list, "email_count": len(email_ids), "status": 200}, safe=False)
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

def get_email_with_ioc(email_data, only_iocs=False):
    try:

        ioc = list(IOC.objects.filter(
            Q(email_ids__startswith=f"{email_data.get("id")}, ")
            | Q(email_ids__endswith=f",{email_data.get("id")}")
            | Q(email_ids__contains=f", {email_data.get("id")},")
            | Q(email_ids__exact=f"{email_data.get("id")}")
        ).values())

        if(only_iocs):
            return ioc
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



def get_recurring_iocs(email_id):
    try:
        iocs = list(IOC.objects.filter(
            Q(email_ids__startswith=f"{email_id}, ")
            | Q(email_ids__endswith=f",{email_id}")
            | Q(email_ids__contains=f", {email_id},")
            | Q(email_ids__exact=f"{email_id}")
        ).values().distinct())

        recurring_iocs = {

        }
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type")
            ioc_detected_at = ioc.get("detected_at")
            ioc_value = ioc.get("value")
            ioc_file_hash = ioc.get("file_hash") or ""
            ioc_count = len(ioc.get("email_ids").split(","))
            ioc_is_malicious = ioc.get("is_malicious")
            if(ioc_count > 1):
                recurring_iocs[ioc_value] = {
                    "file_hash": ioc_file_hash,
                    "count": ioc_count,
                    "detected_at": ioc_detected_at,
                    "type": ioc_type
                }


        return recurring_iocs
    except Exception as e:
        print(f"Error in get_recurring_iocs: {e}")
        return {}
