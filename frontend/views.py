from django.shortcuts import render


# Create your views here.
def login(request):
    return render(request, "login.html")


def adminSignup(request):
    return render(request, "admin/adminSignup.html")


def adminLogin(request):
    return render(request, "admin/adminLogin.html")


def adminPage(request):
    return render(request, "admin/adminPage.html")


def analystPage(request):
    return render(request, "analyst/analystPage.html")


def setupImap(request):
    return render(request, "analyst/setupImap.html")
