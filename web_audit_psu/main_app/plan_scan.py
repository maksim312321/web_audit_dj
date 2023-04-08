import sys
import nmap
import os
import requests
host = sys.argv[1]
print(requests.post('http://127.0.0.1:8000/plan_scan/', json=host))
