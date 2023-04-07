from django.db import models
from django.contrib.auth.models import User

class Hosts(models.Model):
    ip = models.CharField(max_length=16)
    protocol = models.CharField(max_length=3)
    port = models.IntegerField()
    last_scan_date = models.DateTimeField(auto_now=True)
    soft_name = models.CharField(max_length=100)
    soft_version = models.CharField(max_length=100)

class Bdu_vulns(models.Model):
    host = models.ForeignKey(Hosts, on_delete=models.CASCADE)
    bdu_id = models.CharField(max_length=50)
    cve = models.CharField(max_length=50)
    softs = models.TextField(blank=True)
    softs_versions = models.TextField(blank=True)
    cvss_score = models.CharField(max_length=100)
    cvss_vector = models.CharField(max_length=100)
    desc = models.TextField(blank=True)
    found_date = models.DateTimeField(auto_now=True)

class Nist_vulns(models.Model):
    host = models.ForeignKey(Hosts, on_delete=models.CASCADE)
    cve = models.CharField(max_length=50)
    softs = models.TextField(blank=True)
    softs_versions = models.TextField(blank=True)
    cvss_score = models.CharField(max_length=100)
    cvss_vector = models.CharField(max_length=100)
    desc = models.TextField(blank=True)
    found_date = models.DateTimeField(auto_now=True)

class Notify(models.Model):
    host = models.ForeignKey(Hosts, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    mail = models.CharField(max_length=100)

class History(models.Model):
    host = models.ForeignKey(Hosts, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(auto_now=True)
    nist_count = models.IntegerField()
    bdu_count = models.IntegerField()

