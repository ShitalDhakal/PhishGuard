from . models import Role
from . models import User
from django.http import JsonResponse

def getAllRoles(request):
    roles = list(Role.objects.values('role_id', 'role_name'))

    return JsonResponse(roles, safe=False)

