from Mailbox.models import MailBox as mailbox
from django.http import JsonResponse
from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
import imaplib
import json

def insert_imap_server(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            new_imap = mailbox(address=data['address'], app_password=data['app_password'], imap_server=data['imap_server'])

            if(request.session.get('login_user_role') != 'analyst'):
                print(f"Current role: {request.session.get('login_user_role')}")
                return HttpResponse("Only anlayst can setup IMAP!", 405)
            
            new_imap.save()
            return JsonResponse({'message' : 'Saved successfully', 'status': 200})
        
        except Exception as e:
            print(f"Error: {e}")
            return HttpResponse(500)
        
    else:
        return HttpResponse('GET not allowed', 405)
    
def get_mail_data(request):
    data = list(mailbox.objects.all().values())
    return JsonResponse(data, safe=False)


def test_connection(request):
    try:
        data = list(mailbox.objects.all().values())
        mail = imaplib.IMAP4_SSL(data[0]['imap_server'])
        mail.login(data[0]['address'], data[0]['app_password'])
        mail.logout()
        return JsonResponse({'message': 'Connection established', 'status':200})
    
    except Exception as e:
        print(f"Error: {e}")
        return JsonResponse({'message': 'failure', 'status': 500})
    
def change_mail_cred(request):
    try:
        if(request.session.get("login_user_role") == "analyst"):
            data = json.loads(request.body)

            existing = mailbox.objects.first()  # Always work on the single mailbox row

            if existing:
                # Update the existing row
                existing.address      = data["address"]
                existing.app_password = data["app_password"]
                existing.imap_server  = data["imap_server"]
                existing.save()
                return JsonResponse({'message': 'Updated successfully', 'status': 200})
            else:
                # No row exists yet — create one
                mailbox.objects.create(
                    address      = data["address"],
                    app_password = data["app_password"],
                    imap_server  = data["imap_server"],
                )
                return JsonResponse({'message': 'Created successfully', 'status': 200})
        else:
            return JsonResponse({'message': 'Not proper role', 'status': 403})
    except Exception as e:
        print(e)
        return JsonResponse({'message': f'Server error: {str(e)}', 'status': 500})

