import json
import re
# from email.mime.text import MIMEText

# from django.utils import timezone

import pandas
# from django_celery_beat.models import PeriodicTask, IntervalSchedule
from packaging import version
from web_audit_psu.settings import *
from main_app.models import *
import nmap
import smtplib


def mail_handler(new_host, old_bdus, old_nists):
    if len(Bdu_vulns.objects.filter(host=new_host)) > len(old_bdus):
        newBdu = find_diff(Bdu_vulns.objects.filter(host=new_host), old_bdus)
        arrayBDUs = []
        for n in newBdu:
            arrayBDUs.append({'cve': n.cve, 'cvss': n.cvss_score, 'desc': n.desc})
        send_email('maksim.zelenin.01@bk.ru', arrayBDUs, f'Новая уязвимость на {new_host.ip}:{new_host.port} БДУ ФСТЭК')

    if len(Nist_vulns.objects.filter(host=new_host)) > len(old_nists):
        newNist = find_diff(Nist_vulns.objects.filter(host=new_host), old_nists)
        arrayNists = []
        for n in newNist:
            arrayNists.append({'cve': n.cve, 'cvss': n.cvss_score, 'desc': n.desc})

        mails = Notify.objects.filter(host=new_host)
        for m in mails:
            send_email(m.mail, arrayNists, f'Новая уязвимость на {new_host.ip}:{new_host.port} NIST')
def find_diff(A, B):
    diff = []
    for all in A:
        found = False
        for sub in B:
            if sub.cve == all.cve:
                found = True
                break
        if not found:
            diff.append(all)
    return diff

def send_email(address, data, type):
    smtpObj = smtplib.SMTP_SSL('smtp.mail.ru', 465)
    smtpObj.login('web.audit.psu@mail.ru', 'sqzmMFmNGqv7nQAUSrBu')

    mailHtml = ''
    for cve in data:
        mailHtml += f'<hr> <div><span>{cve["cve"]}</span> <div>Оценка CVSS: <b>{cve["cvss"]}</b></div> <div>Описание: <span>{cve["desc"]}</span></div></div>'
    mailHtml += '<hr>'
    body = "\r\n".join((f"From: web.audit.psu@mail.ru", f"To: {address}",
                        f"Subject: {type}", 'MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8', "",
                        mailHtml
                        ))

    smtpObj.sendmail("web.audit.psu@mail.ru", address, body.encode('utf-8'))
    smtpObj.quit()
def search_bdu(cur_soft_title, cur_ver, host):
    Bdu_vulns.objects.filter(host=host).delete()
    bdu_fstek_table = pandas.read_excel(VULLIST_XLSX_ROOT, header=2)
    for row_index in bdu_fstek_table.index:
        soft_title = str(bdu_fstek_table['Название ПО'][row_index])
        versions = bdu_fstek_table['Версия ПО'][row_index]
        if cur_soft_title.lower() in soft_title.lower():
            cve_row = bdu_fstek_table['Идентификаторы других систем описаний уязвимости'][row_index]
            for current_service_version in versions.split(','):
                begin_version = None
                end_version = None

                if 'от' in current_service_version:
                    begin_version = re.search('[^\d.]?[\d.]+[^\d.]?', str(current_service_version) + ' ')[0]
                    while re.search('[\d]', begin_version[0]) is None:
                        begin_version = begin_version[1:]
                    while re.search("[\d]", begin_version[-1]) is None:
                        begin_version = begin_version[:-1]

                if 'до' in current_service_version:
                    end_version = re.search('[^\d.]?[\d.]+[^\d.]?', str(current_service_version) + ' ')
                    end_version = end_version[0]

                    while re.search('[^\d]', end_version[0]):
                        end_version = end_version[1:]
                    while re.search('[^\d]', end_version[-1]):
                        end_version = end_version[:-1]

                    cur_ver = re.search('[^\d.]?[\d.]+[^\d.]?', str(cur_ver) + ' ')
                    cur_ver = cur_ver[0]

                    while re.search('[^\d]', cur_ver[0]):
                        end_version = end_version[1:]
                    while re.search('[^\d]', cur_ver[-1]):
                        cur_ver = cur_ver[:-1]

                flag_begin_vesion = ((begin_version is not None) and (end_version is None) and (
                        version.parse(begin_version) <= version.parse(cur_ver)))
                flag_end_vesion = ((begin_version is None) and (end_version is not None) and (
                        version.parse(cur_ver) <= version.parse(end_version)))
                flag_both_vesion = ((begin_version is not None) and (end_version is not None) and (
                        version.parse(begin_version) <= version.parse(cur_ver)) and (
                                            version.parse(cur_ver) <= version.parse(end_version)))
                if flag_begin_vesion or flag_end_vesion or flag_both_vesion:
                    new_bdu = Bdu_vulns(host=host,
                                        bdu_id=str(bdu_fstek_table['Идентификатор'][row_index]),
                                        cve=str(cve_row),
                                        softs=str(bdu_fstek_table['Название ПО'][row_index]),
                                        softs_versions=str(bdu_fstek_table['Версия ПО'][row_index]),
                                        cvss_score=str(bdu_fstek_table['Уровень опасности уязвимости'][row_index]),
                                        cvss_vector=str(bdu_fstek_table['CVSS 3.0'][row_index]),
                                        desc=str(bdu_fstek_table['Описание уязвимости'][row_index])
                                        )
                    new_bdu.save()

                    break
    return len(Bdu_vulns.objects.filter(host=host))

def search_nist(cur_soft_title, cur_ver, host):
    Nist_vulns.objects.filter(host=host).delete()
    regex = re.compile(f'({cur_soft_title})', re.I)
    for entry in json.load(open(NIST_JSON_ROOT, 'r', encoding='utf-8')):
        if 'cve' in entry:
            desc = entry['configurations']['nodes']
            for d in desc:
                for cpe in d['cpe_match']:
                    if regex.search(cpe['cpe23Uri']) != None:
                        try:
                            if 'versionEndExcluding' in cpe and version.parse(cur_ver) < version.parse(cpe['versionEndExcluding']):
                                if 'versionStartExcluding' not in cpe or 'versionStartExcluding' in cpe and version.parse(cur_ver) > version.parse(cpe['versionStartExcluding']):

                                    if len(entry['configurations']['nodes'][0]['cpe_match']) == 0:
                                        break

                                    version_formated = ''
                                    if entry['configurations']['nodes'][0]['cpe_match'][0].get(
                                            'versionStartExcluding') != None:
                                        version_formated += 'от ' + entry['configurations']['nodes'][0]['cpe_match'][0].get(
                                            'versionStartExcluding') + ' '
                                    if entry['configurations']['nodes'][0]['cpe_match'][0].get('versionEndExcluding') != None:
                                        version_formated += 'до ' + entry['configurations']['nodes'][0]['cpe_match'][0].get(
                                            'versionEndExcluding')

                                    new_nist = Nist_vulns(host=host,
                                                        cve=str(entry['cve']['CVE_data_meta']['ID']),
                                                        softs=str(cur_soft_title),
                                                        softs_versions=str(version_formated),
                                                        cvss_score=str(entry['impact']['baseMetricV3']['cvssV3']['baseScore']),
                                                        cvss_vector=str(entry['impact']['baseMetricV3']['cvssV3']['vectorString']),
                                                        desc=str(entry['cve']['description']['description_data'][0]['value'])
                                                        )
                                    new_nist.save()
                                    break
                        except:
                            break
    return len(Nist_vulns.objects.filter(host=host))


def save_scan_result(scan_raw_result):
    old_nists = None
    old_bdus = None

    for host, result in scan_raw_result['scan'].items():
        if result['status']['state'] == 'up':
            protocols = []
            if result.get('tcp') != None:
                protocols.append('tcp')
            if result.get('udp') != None:
                protocols.append('udp')

            for protocol in protocols:
                for port in result[protocol]:
                    cur_ver = result[protocol][port]['version']
                    cur_soft_title = result[protocol][port]['product']
                    if ' ' in cur_soft_title:
                        cur_soft_title = cur_soft_title.split()[0].lower()

                    if cur_ver and cur_soft_title:
                        new_host = Hosts.objects.filter(ip=host, protocol=protocol, port=str(port), soft_name=cur_soft_title, soft_version=cur_ver)
                        if len(new_host) == 0:
                            new_host = Hosts(ip=host, protocol=protocol, port=str(port), soft_name=cur_soft_title, soft_version=cur_ver)
                        else:
                            new_host = new_host[0]

                        new_host.save()

                        old_bdus = Bdu_vulns.objects.filter(host=new_host)
                        old_nists = Nist_vulns.objects.filter(host=new_host)

                        History(host=new_host,
                                bdu_count=search_bdu(cur_soft_title, cur_ver, new_host),
                                nist_count=search_nist(cur_soft_title, cur_ver, new_host)
                                ).save()

                        mail_handler(new_host, old_bdus, old_nists)
                    else:
                        if not cur_ver:
                            print('VERSION IS NOT DEFINE')
                        if not cur_soft_title:
                            print('SOFT IS NOT DEFINE')


def insert_nmap_to_path():
    NMAP_PATH = f';D:\\psu\\11_trim\\web_audit_dj\\Nmap;'
    if (os.environ['PATH'].find(NMAP_PATH) == -1):
        os.environ['PATH'] += NMAP_PATH
def nmap_scan(host):
    insert_nmap_to_path()
    nm = nmap.PortScanner()
    scan_raw_result = nm.scan(hosts=host, arguments='-v -n -A')
    save_scan_result(scan_raw_result)

    # PeriodicTask.objects.create(
    #     name='Scan Host {}'.format(host),
    #     task='nmap_scan',
    #     interval=IntervalSchedule.objects.get(every=2, period=IntervalSchedule.MINUTES),
    #     args=json.dumps(host),
    #     start_time=timezone.now(),
    # )
