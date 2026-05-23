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
from Mailbox.services import setup_imap

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
    path('testImapConnection/', setup_imap.test_connection)
]
