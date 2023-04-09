from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import logout, login, authenticate
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import FormView
import json

from main_app.nmap_functions import *

def insert_nmap_to_path():
    NMAP_PATH = f';D:\\psu\\11_trim\\web_audit_dj\\Nmap;'
    if (os.environ['PATH'].find(NMAP_PATH) == -1):
        os.environ['PATH'] += NMAP_PATH

def index(request):
    return render(request, 'home.html')

class Login(FormView):
    form_class = AuthenticationForm
    template_name = 'login.html'
    success_url = '/'
    def post(self, request):
        form = self.get_form()
        if form.is_valid():
            form.clean()
            user = authenticate(
                request,
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password"],
            )
            login(request, user)
            return redirect("/")
        else:
            return redirect("/")

def logout_user(request):
    logout(request)
    return redirect('/')

def vulns(request, id, db):
    if db == 'bdu':
        vulns = Bdu_vulns.objects.filter(host_id=id)
    else:
        vulns = Nist_vulns.objects.filter(host_id=id)
    ctx = {'vulns': vulns}
    return render(request, 'vulns.html', ctx)

def scan(request):
    return render(request, 'scan.html')

def notify(request):
    ctx = {'notifies': Notify.objects.filter(user=request.user)}
    return render(request, 'notify.html', ctx)

def add_notify(request):
    host = Hosts.objects.filter(ip=request.POST['host'])
    for h in host:
        notify = Notify(user=request.user, mail=request.POST['mail'], host=h)
        notify.save()
    return redirect('notify')
def delete_notify(request):
    for k in request.POST:
        if k != 'csrfmiddlewaretoken':
            Notify.objects.get(pk=k).delete()
    return redirect('notify')
def scan_host(request):
    if not request.user.is_authenticated:
        return redirect('/')

    host = request.POST['host']
    if host is None:
        return HttpResponse("host empty")

    nmap_scan(host)

    return HttpResponse(f"host scanned")

def history(request, id):
    host = Hosts.objects.get(id=id)
    hist_array = []
    history = History.objects.filter(host=host)
    for h in history:
        hist_array.append({
            'host': h.host.ip,
            'scan_date': h.scan_date,
            'nist_count': h.nist_count,
            'bdu_count': h.bdu_count,
        })
    ctx = {'history': history,
           'history_json': json.dumps(hist_array, indent=4, sort_keys=True, default=str)
           }
    return render(request, 'history.html', ctx)

def hosts(request):
    if not request.user.is_authenticated:
        return redirect('/')

    hosts = Hosts.objects.all()
    for h in hosts:
        h.bdu_vulns_count = len(Bdu_vulns.objects.filter(host=h))
        h.nist_vulns_count = len(Nist_vulns.objects.filter(host=h))

    ctx = {'hosts': hosts}
    return render(request, 'hosts.html', ctx)

def plan(request):
    hosts = Hosts.objects.all()

    for h in hosts:
        if (len(Plan.objects.filter(host=h)) == 0):
            h.plan = ''
        else:
            h.plan = Plan.objects.filter(host=h)[0].plan_value
    ctx = {'hosts': hosts}

    return render(request, 'plan.html', ctx)

def set_plan(request):
    data = json.loads(request.POST['plan_type'])
    host = Hosts.objects.get(pk=data[0])
    if (len(Plan.objects.filter(host=host)) > 0):
        p = Plan.objects.filter(host=host)[0]
        p.plan_value = data[1]
        p.save()
    else:
        p = Plan(host=host, plan_value=data[1])
        p.save()

    # 0 8 * * * /usr/bin /python3 /home/scan/myprojectdir/main_app/update_nist.py
    # 0 8 * * * /usr/bin/python3 /home/scan/myprojectdir/main_app/update_bdu_fstek.py

    for p in Plan.objects.all():
        print(f'{p.plan_value} /usr/bin/python3 /home/scan/myprojectdir/main_app/plan_scan.py {p.host.ip}:{p.host.port}')
    return plan(request)

@csrf_exempt
def plan_scan(request):
    if request.body:
        host = json.loads(request.body)
        nmap_scan(host)
        return HttpResponse('Ready')
    else:
        return HttpResponse('error: not post request method')