import os
from dotenv import load_dotenv
import httpx
import time
from fastapi import FastAPI
import uvicorn

app = FastAPI()
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
  - incorperate more than the current API based on the chance some APIs cannot parse some sites due to anti botting, solution is use multiple tools
    incorperate a final score of the likelyhood a site is malicious 
"""

"""
TODO 

- Get Url (done)
- Extract the verdict from the API call (done)
- Pass that verdict to the front-end

"""
@app.get("/")
def getData():
# Creates a URL Scan tied to the UUID, The UUID is needed to exactract the verdict if a URL sight is Malicious 
    r = httpx.post(
         f"https://api.cloudflare.com/client/v4/accounts/{AccountID}/urlscanner/v2/scan",
         json={"url": "https://developers.cloudflare.com/radar/investigate/url-scanner/"},
         headers={"Authorization": f"Bearer {apiKey}"},
    )
    data = r.json()
    print(data)
    uuid = data["uuid"]

#Use var uuid to access to get and access the data collected from the API
#The cloudflare API Takes time to run Requiring 10 - 30 seconds, The Loop below will continue to check the status
    reportCall= f"https://api.cloudflare.com/client/v4/accounts/{AccountID}/urlscanner/v2/result/{uuid}"
    maxAttempts = 20
    reportJsonData = ""

    for attempt in range(maxAttempts):
        r = httpx.get(reportCall, headers={"Authorization": f"Bearer {apiKey}"})

        if r.status_code == 200:
            reportJsonData = r.json()
            return reportJsonData["verdicts"]["overall"]

        elif r.status_code == 404:
            print("Scan is still processing")
            time.sleep(10)

        else:
            print("Unexpected Error has occurred")

# The API offeres a lot of data we can use for now we will focus on the if it returns True or False if a site is malicious
if __name__ == "__main__": uvicorn.run(app, host="127.0.0.1", port=5000)


