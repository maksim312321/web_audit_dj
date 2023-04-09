from django.urls import path
from django.views.generic import TemplateView

from .views import *

urlpatterns = [
    path('', index, name='home'),
    path('login/', Login.as_view(), name='login'),
    path('logout/', logout_user, name='logout'),
    path('hosts/', hosts, name='hosts'),
    path('<int:id>/<str:db>/', vulns, name='vulns'),
    path('scan_host/', scan_host, name='scan_host'),
    path('scan/', scan, name='scan'),
    path('notify/', notify, name='notify'),
    path('add_notify/', add_notify, name='add_notify'),
    path('delete_notify/', delete_notify, name='delete_notify'),
    path('history/<int:id>/', history, name='history'),
    path('plan_scan/', plan_scan, name='plan_scan'),
    path('plan/', plan, name='plan'),
    path('set_plan/', set_plan, name='set_plan'),
]