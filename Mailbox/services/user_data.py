import email
import json
from urllib import response
from django.http import HttpResponse, JsonResponse

from analyzer.models import IOC, ApiKeys
from Mailbox.models import EmailRecord, MailBox
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
        if request.body:
            data = json.loads(request.body)

        ioc_query = IOC.objects.all()

        if data.get("email") and data.get("email") != "all":
            email_ids = EmailRecord.objects.filter(
                recipient__icontains=data.get("email"), 
                scanned=True
            ).values_list("id", flat=True)

            email_q_filters = Q()
            for e_id in email_ids:
                email_q_filters |= (
                    Q(email_ids__startswith=f"{e_id}, ")
                    | Q(email_ids__endswith=f",{e_id}")
                    | Q(email_ids__contains=f", {e_id},")
                    | Q(email_ids__exact=f"{e_id}")
                )
            
            if email_ids:
                ioc_query = ioc_query.filter(email_q_filters)
            else:
                ioc_query = ioc_query.none()
        else:
            if request.session.get('login_user_role') != 'analyst':
                return JsonResponse({"message": "Only analyst can fetch all IOCs!", "status": 405}, safe=False)

        if data.get("ioc_type"):
            ioc_query = ioc_query.filter(ioc_type__icontains=data.get("ioc_type"))
            
        if data.get("search_text"):
            ioc_query = ioc_query.filter(value__icontains=data.get("search_text"))

        if data.get("verdict"):
            if data.get("verdict") == "malicious":
                ioc_query = ioc_query.filter(is_malicious=True)
            elif data.get("verdict") == "safe":
                ioc_query = ioc_query.filter(is_malicious=False)
            else:
                ioc_query = ioc_query.filter(is_malicious__isnull=True)

        final_data = list(ioc_query.values())
        for ioc in final_data:
            if(ioc.get("email_ids")):
                recurring_iocs = ioc.get("email_ids").split(",")
                ioc["recurring_iocs"] = len(recurring_iocs)

        final_data.sort(
            key = lambda x: x["recurring_iocs"],
            reverse = True
        )

        return JsonResponse({"data": final_data, "status": 200}, safe=False)
        
    except Exception as e:
        print(f"Error in get_ioc_overview: {e}")
        return HttpResponse(status=500)

def get_ioc_by_email_id(id):
    try:

        ioc = IOC.objects.filter(
            Q(email_ids__startswith=f"{id}, ")
            | Q(email_ids__endswith=f",{id}")
            | Q(email_ids__contains=f", {id},")
            | Q(email_ids__exact=f"{id}")
        )

        return ioc
    except Exception as e:
        print(e)
        return {}
    

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

def get_mail_cred(request):
    try:
        cred = MailBox.objects.first()

        if (request.session.get('login_user_role') != 'analyst'):
            return JsonResponse({"message": "Only analyst can fetch mailbox credentials!", "status": 405}, safe=False)
        if cred:
            data = {
                "address": cred.address,
                "app_password": cred.app_password,
                "imap_server": cred.imap_server
            }
            return JsonResponse({"data": data, "status": 200}, safe=False)
        else:
            return JsonResponse({"message": "No mailbox credentials found.", "status": 404}, safe=False)
    except Exception as e:
        print(f"Error in get_mail_cred: {e}")
        return HttpResponse(status=500)
    
def insert_update_api_key(request):
    try:
        if request.session.get('login_user_role') != 'analyst':
            return JsonResponse({"message": "Only analyst can update API keys!", "status": 405}, safe=False)
        else:
            data = {}
            if request.body:
                data = json.loads(request.body)
            abuseipdb_key = data.get("abuseipdb_key")
            virustotal_key = data.get("virustotal_key")
            malwarebazaar_key = data.get("malwarebazaar_key")
            google_safe_browsing_key = data.get("google_safe_browsing_key")

            api_keys, created = ApiKeys.objects.get_or_create(id=1)
            api_keys.abuseipdb_key = abuseipdb_key
            api_keys.virustotal_key = virustotal_key
            api_keys.malwarebazaar_key = malwarebazaar_key
            api_keys.google_safe_browsing_key = google_safe_browsing_key
            api_keys.save()

            return JsonResponse({"message": "API keys updated successfully.", "status": 200}, safe=False)
    except Exception as e:
        print(f"Error in insert_update_api_key: {e}")
        return HttpResponse(status=500)
    
def get_api_keys(request):
    try:
        if request.session.get('login_user_role') != 'analyst':
            return JsonResponse({"message": "Only analyst can fetch API keys!", "status": 405}, safe=False)
        else:
            api_keys = ApiKeys.objects.first()
            if api_keys:
                data = {
                    "abuseipdb_key": api_keys.abuseipdb_key,
                    "virustotal_key": api_keys.virustotal_key,
                    "malwarebazaar_key": api_keys.malwarebazaar_key,
                    "google_safe_browsing_key": api_keys.google_safe_browsing_key
                }
                return JsonResponse({"data": data, "status": 200}, safe=False)
            else:
                return JsonResponse({"message": "No API keys found.", "status": 404}, safe=False)
    except Exception as e:
        print(f"Error in get_api_keys: {e}")
        return HttpResponse(status=500)