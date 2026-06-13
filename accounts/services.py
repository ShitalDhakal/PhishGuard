from . models import User as modelUser
from django.http import JsonResponse
from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
import json

def get_admin_count():
    adminCount = modelUser.objects.filter(role='admin').count()
    return adminCount

def adminCountCheck(request):
    adminCount = get_admin_count()
    request.session['adminCount'] = adminCount
    return HttpResponse(adminCount)


@csrf_exempt
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
    
@csrf_exempt
def userLogin(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = modelUser.objects.get(username=data['username'], role=data['role'])
            print(user)
            if(check_password(data['password'], user.password)):
                request.session['login_user_id'] = user.user_id
                request.session['login_user_role'] = user.role
                return HttpResponse(200)
            else:
                return HttpResponse(401)
            
        except Exception as e:
            print(f"Error: {e}")
            return HttpResponse(500)
    else:
        return HttpResponse(405)


def get_logged_in_data(request):
    user_id = request.session.get('login_user_id')
    if not user_id:
        return JsonResponse({'id': 0, 'error': 'User not logged in!'}, status=401)
    
    data = {
        'id': user_id,
        'role': request.session.get('login_user_role')
    }

    return JsonResponse(data, safe=False)
