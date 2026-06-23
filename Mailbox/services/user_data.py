import json
from django.http import HttpResponse, JsonResponse

from analyzer.models import IOC
from Mailbox.models import EmailRecord

def fetch_ioc(request):
    try:
        data = {}
        if(request.body):
            data = json.loads(request.body)\
        
        ioc_list = []
        if(data.get('email')):
            ioc_list = IOC.objects.filter(email=data['email']).values()
        else:
            ioc_list = IOC.objects.all().values()
        return JsonResponse(list(ioc_list), safe=False)
    except Exception as e:
        print(f"Error: {e}")
        return HttpResponse(500)
    
def load_ioc(request):
    try:
        emails = E
    except Exception as e:
        print(f"Error: {e}")
        return HttpResponse(500)