import requests
import re
URL = "https://bazaar.abuse.ch/browse/"
r = requests.get(URL)
x=re.findall("[A-Fa-f0-9\d]{64}",r.text)
print(x)

