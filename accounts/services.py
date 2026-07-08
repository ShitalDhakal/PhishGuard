from httpx import request

from . models import User as modelUser
from django.http import JsonResponse
from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from Mailbox.services.email_sender import sendEmail
import json

def get_admin_count():
    adminCount = modelUser.objects.filter(role='admin').count()
    return adminCount

def adminCountCheck(request):
    adminCount = get_admin_count()
    request.session['adminCount'] = adminCount
    return HttpResponse(adminCount)


def userRegister(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            newUser = modelUser(username=data['username'], email=data['email'], password=make_password(data['password']), created_date=timezone.now(), role=data['role'])
            if(data['role'] == 'admin'):
                adminCount = get_admin_count()
                if(adminCount > 0):
                    return HttpResponse(405)
                
            if(request.session.get('login_user_role') != 'admin' and adminCount > 0):
                return HttpResponse("Only admin can create users!", 405)

            newUser.save()
            return HttpResponse(200)
        except Exception as e:
            print(f"Error: {e}")
            return HttpResponse(500)
    else:
        return HttpResponse(500)
    
def userLogin(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = modelUser.objects.get(username=data['username'], role=data['role'])
            print(user)
            if(check_password(data['password'], user.password)):
                request.session['login_user_id'] = user.user_id
                request.session['login_user_role'] = user.role
                return JsonResponse({"message":"Successful login.", "status": 200})
            else:
                return JsonResponse({"message":"Wrong Credentials.", "status": 403})
            
        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({"message":"Server error", "status":500})
    else:
        return JsonResponse({"message":"Method not allowed!", "status":403})


def get_logged_in_data(request):
    user_id = request.session.get('login_user_id')
    if not user_id:
        return JsonResponse({'id': 0, 'error': 'User not logged in!'}, status=401)
    
    data = {
        'id': user_id,
        'role': request.session.get('login_user_role')
    }

    return JsonResponse(data, safe=False)


def change_user_cred(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body);
            user = modelUser.objects.get(user_id=data['userId'])
            if(check_password(data["oldPwd"], user.password)):
                user.username = data["newUsername"]
                user.password = make_password(data["newPwd"])
                user.email = data['newEmail']
                user.modified_date = timezone.now()
                email_subject = "PhishGuard - User Credentials Changed"
                email_body = f"Hello {user.username},\n\nYour account credentials has been changed. Please contact your administrator about new credentials. Thank you.";
                sendEmail(user.email, email_subject, email_body)
                user.save()
                return JsonResponse({"message":"Successfully changed credentials", "status":200})
            else:
                return JsonResponse({"message":"Wrong Credentials", "status":403})
        except Exception as e:
            print(e)
            return JsonResponse({"message":"Wrong Credentials", "status":500})


    else:
        return JsonResponse({"message":"Method not allowed", "status":403})
    

def get_all_users(request):
        try:
            if(request.session.get('login_user_role') in {"admin", "analyst"}):
                    user = list(modelUser.objects.values("user_id", "username", "email", "role", "created_date", "modified_date"))
                    return JsonResponse({"data":user, "status": 200})
            else:
                return JsonResponse({"message":"You are not logged in as proper role", "status":403})
        except Exception as e:
            print(e)
            return JsonResponse({"message":"Server error", "status":500})
        
def delete_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = modelUser.objects.get(user_id=data['userId'])
            if(check_password(data["oldPwd"], user.password)):
                user.delete()
                return JsonResponse({"message":"User deleted successfully", "status":200})
            else:
                return JsonResponse({"message":"Wrong Credentials", "status":403})
        except Exception as e:
            print(e)
            return JsonResponse({"message":"Server error", "status":500})
    else:
        return JsonResponse({"message":"Method not allowed", "status":403})
    
def getCurrentRole(request):
    return JsonResponse({"role": request.session.get('login_user_role')}, safe=False)