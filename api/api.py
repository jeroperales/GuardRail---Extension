import os
from dotenv import load_dotenv
import httpx
import time
from fastapi import FastAPI
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
#This allows specified domans to communicate with the backend
app = FastAPI()
origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Allows us to use Enviroment Varibles
load_dotenv()
apiKey = os.getenv("TOKEN")
AccountID = os.getenv("ACCOUNT_ID")

# Schema defining the data we are recieving from the front end
class Url(BaseModel):
    url: str


"""

Function 1 - taking in a Link/Url and comparing it to potential malicicous links

What we want to catch:
- Brand impersonation (phising scheames)
- Known malicious links 
- Detecting if a site is malicious 

TODO:

- Get Url (done)
- Extract the verdict from the API call (done)
- Pass that verdict to the front-end (done)

Milestones:
- Established getting data from the API and inputting it to the frontend (done)
- Make this readable to the actual frontend itself 

"""

# So we need to get the data from the front end to the backend, so we post it to our backend server
@app.post("/scan/")
async def getUrl(url: Url):
    print(url)
    return url


@app.get("/")
def getData():
# Creates a URL Scan tied to the UUID, The UUID is needed to exactract the verdict if a URL sight is Malicious
    urlToScan = ""
    r = httpx.post(
         f"https://api.cloudflare.com/client/v4/accounts/{AccountID}/urlscanner/v2/scan",
         json={"url": f"https://{urlToScan}"},
         headers={"Authorization": f"Bearer {apiKey}"},
    )
    data = r.json()
    print(data)
    uuid = data["uuid"]
    print(data)
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


