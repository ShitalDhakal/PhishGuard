"""
URL configuration for PhishGuard project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from accounts import services as accountService
from frontend import views 
from Mailbox.services import setup_imap, imap_fetcher, user_data
from analyzer.services import analyze_email, analyzed_data_apis

urlpatterns = [
    path('', views.login),
    path('adminSignup/', views.adminSignup),
    path('userRegister/', accountService.userRegister),
    path('userLogin/', accountService.userLogin),
    path('adminPage/', views.adminPage),
    path('analystPage/', views.analystPage),
    path('setupImap/', views.setupImap),
    path('checkAdminCount/', accountService.adminCountCheck),
    path('getLoginData/', accountService.get_logged_in_data),
    path('insertUpdateImap/', setup_imap.insert_imap_server),
    path('getMailData/', setup_imap.get_mail_data),
    path('testImapConnection/', setup_imap.test_connection),
    path('fetch_emails/', imap_fetcher.fetch_emails),
    path('read_mail_from_db/', imap_fetcher.read_mail_from_db),
    path('change_user_cred/', accountService.change_user_cred),
    path('changeCred/', views.changeCred),
    path('get_all_users/', accountService.get_all_users),
    path('changeMailboxCred/', views.changeMailboxCred),
    path('change_mail_cred/', setup_imap.change_mail_cred),
    path('employeePage/', views.employeePage),
    path('fetch_ioc/', user_data.fetch_ioc),
    path('get_ioc_overview/', user_data.get_ioc_overview),
    path('userList/', views.userList),
    path('delete_user/', accountService.delete_user),
    path('get_email_overview/', user_data.get_email_overview),
    path('email_data/', views.email_data),
    path('analyze_email/', analyze_email.analyze_email),
    path('get_email_data_and_scores/', analyzed_data_apis.get_email_data_and_scores),
    path('update_risk_score/', analyzed_data_apis.update_risk_score)
]
