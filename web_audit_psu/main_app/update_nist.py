import json
import urllib.request
import ssl
import os
import gzip

years = [2020, 2021, 2022, 2023]
CVEs = []

for year in years:
    destination = 'nvdcve-1.1-' + str(year) + '.json.gz'
    if os.path.exists(destination):
        os.remove(destination)

    ssl._create_default_https_context = ssl._create_unverified_context
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-' + str(year) + '.json.gz'

    opener = urllib.request.URLopener()
    opener.addheader('User-Agent', 'Mozilla/5.0')
    filename, headers = opener.retrieve(url, destination)

    with gzip.open('nvdcve-1.1-' + str(year) + '.json.gz', 'rb') as f:
        file_content = f.read()
        data = json.loads(file_content)['CVE_Items']
        CVEs = CVEs + data

    os.remove(destination)

json_object = json.dumps(CVEs)

with open("nist_vulns.json", "w") as outfile:
    outfile.write(json_object)
print(len(CVEs))