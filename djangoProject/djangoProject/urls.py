"""djangoProject URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
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
from . import views


urlpatterns = [
    path('admin/', admin.site.urls),
    path('alert-admin/', views.alert_admin),
    path('alert-hardware/', views.alert_hardware),
    path('admin-config/', views.config_admin),
    path('common-config/', views.config_common),
    path('search/', views.search),
    path('alert-hardware-post/', views.alert_hardware_post),
    path('alert-admin-post/', views.alert_admin_post),
    path('search-post/', views.search_post),
    path('login/', views.login),
    path('reg-post/', views.reg_post),
    path('risk-post/', views.risk_post),
    path('alert-post/', views.alert_post),
    path('interval-post/', views.interval_post),
    path('proxy-post/', views.proxy_post),
]
