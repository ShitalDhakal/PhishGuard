from django.shortcuts import render

# Create your views here.
def login(request):
    return render(request, 'login.html')

def adminSignup(request):
    return render(request, 'adminSignup.html')

def adminLogin(request):
    return render(request, 'adminLogin.html')

def adminPage(request):
    return render(request, 'adminPage.html')