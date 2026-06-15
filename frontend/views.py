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


def changeCred(request):
    return render(request, "changeCred.html")

def ban(request):
    return render(request, "admin/ban.html")

def changeMailboxCred(request):
    return render(request, "analyst/change_mailbox_cred.html")


def employeePage(request):
    return render(request, "employee/employeePage.html")