import urllib.request
import ssl
import os

destination = 'vullist.xlsx'
if os.path.exists(destination):
    os.remove(destination)

ssl._create_default_https_context = ssl._create_unverified_context
url = 'https://bdu.fstec.ru/files/documents/vullist.xlsx'

opener = urllib.request.URLopener()
opener.addheader('User-Agent', 'Mozilla/5.0')
filename, headers = opener.retrieve(url, destination)