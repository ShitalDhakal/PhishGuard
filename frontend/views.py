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

def userList(request):
    return render(request, "admin/userList.html")

def email_data(request):
    return render(request, "analyst/emailData.html")

def analyst_ioc_investigation(request):
    return render(request, "analyst/analyst_ioc_investigation.html")

def analyst_account_manage(request):
    return render(request, "analyst/analyst_account_manage.html")

def email_data_emp(request):
    return render(request, "employee/email_data_emp.html")

def emp_ioc_overview(request):
    return render(request, "employee/emp_ioc_overview.html")

def emp_account_manage(request):
    return render(request, "employee/emp_account_manage.html")