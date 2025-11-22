import sys
import requests

#Change webhook here
webhookurl = "XXXXXXXXXXXXX"
data = {"content": str(sys.argv[1])}
response = requests.post(webhookurl, json=data)
print(response.status_code)
print(response.content)
