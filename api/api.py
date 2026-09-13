import os
from dotenv import load_dotenv
import httpx

load_dotenv()

# Allows us to use Enviroment Varibles
apiKey = os.getenv("TOKEN")
AccountID = os.getenv("ACCOUNT_ID")


"""

Function 1 - taking in a Link/Url and comparing it to potential malicicous links

What we want to catch:
- Brand impersonation (phising scheames)
- Known malicious links

methods:
- get data using external APIs and compare it to the data to the link to detect malicious activity 
  - Virus Total API
  - urlscan.io API
  - Google Safe Browsing API `
"""


r = httpx.post(
    f"https://api.cloudflare.com/client/v4/accounts/{AccountID}/urlscanner/v2/scan",
    json={"url": "https://www.google.com"},
    headers={"Authorization": f"Bearer {apiKey}"},
)
print(r)
