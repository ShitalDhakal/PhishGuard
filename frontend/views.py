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

import base64
import hashlib
import hmac
import uuid
from django.http import JsonResponse
from django.shortcuts import render


def initiate_esewa_payment(request):
    # Your "certain criteria meets" condition here
    # e.g., if criteria_not_met: return JsonResponse(...)

    # 1. Setup eSewa UAT (Testing) Credentials
    merchant_id = "EPAYTEST"
    secret_key = "8gBm/:&EnhH.1/q"  # Standard eSewa Test Secret Key
    initiate_url = "https://rc-epay.esewa.com.np/api/epay/main/v2/form"

    # 2. Dynamic Transaction details
    amount = "100.00"  # Must keep two decimal places as string
    transaction_uuid = str(uuid.uuid4())[:10]  # Unique ID for the order

    # 3. Generate the strict signature string (No spaces after commas!)
    data_to_sign = f"total_amount={amount},transaction_uuid={transaction_uuid},product_code={merchant_id}"

    # 4. Sign via HMAC-SHA256 and encode to Base64
    secret_bytes = secret_key.encode("utf-8")
    data_bytes = data_to_sign.encode("utf-8")
    hash_obj = hmac.new(secret_bytes, data_bytes, hashlib.sha256).digest()
    signature = base64.b64encode(hash_obj).decode("utf-8")

    # 5. Context to send to frontend form
    context = {
        "initiate_url": initiate_url,
        "amount": amount,
        "transaction_uuid": transaction_uuid,
        "merchant_id": merchant_id,
        "signature": signature,
        "success_url": "http://127.0.0.1:8000/payment-success/",  # Change to your success route
        "failure_url": "http://127.0.0.1:8000/payment-success/",
    }

    return render(request, "esewa_redirect.html", context)

def payment_success(request):
    # Here you can verify the payment with eSewa's API if needed
    # For now, we just mark the payment as successful in our database
    from accounts.models import EsewaPayment

    payment_record, created = EsewaPayment.objects.get_or_create(id=1)
    payment_record.is_paid = True
    payment_record.save()

    return render(request, "payment_success.html", {"message": "Payment Successful!"})