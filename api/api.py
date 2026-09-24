import os
from dotenv import load_dotenv
import httpx
import time
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

#This allows specified domains to communicate with the backend
app = FastAPI()
origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:5050",
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

Milestones:
- Separate 


"""


"""
Since data is being used at the same time we can combine the functions as one

- We need to use regex to detect https// in the beginning or not in both the frontend and backend

- We need to detect edge cases such as .sites and propper error handling for bad request i.e 
  a site that does not exist we need to let the user know 
"""

#Cloudflare API Request and Response 
def analyzeUrl(url):
# Creates a URL Scan tied to the UUID, The UUID is needed to exactract the verdict if a URL sight is Malicious
    #
    
    r = httpx.post(
         f"https://api.cloudflare.com/client/v4/accounts/{AccountID}/urlscanner/v2/scan",
         json={"url": f"https://{url}"},
         headers={"Authorization": f"Bearer {apiKey}"},
    )
    try:
        r.raise_for_status()
    except httpx.HTTPStatusError:
        data = r.json()
        #print(f"Error response {data["status"]} while requesting {data["message"]}.")
        return PlainTextResponse(data["message"], status_code=data["status"])
    

    data = r.json()
    print(data)
    uuid = data["uuid"]
    print(data)

#Use var uuid to get and access the data collected from the API
#The cloudflare API Takes time to run Requiring 10 - 30 seconds, The Loop below will continue to check the status every 10 seconds 
    reportCall= f"https://api.cloudflare.com/client/v4/accounts/{AccountID}/urlscanner/v2/result/{uuid}"
    maxAttempts = 20
    reportJsonData = ""

    for attempt in range(maxAttempts):
        r = httpx.get(reportCall, headers={"Authorization": f"Bearer {apiKey}"})

        if r.status_code == 200:
            reportJsonData = r.json()
            # print(reportJsonData)
            return reportJsonData["verdicts"]["overall"]["malicious"]

        elif r.status_code == 404:
            print("Scan is still processing")
            time.sleep(10)

        else:
            print("Unexpected Error has occurred")


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

#Takes in the URL POSTed from the user and runs the process of analyzing the URL 
@app.post("/scan/")
async def getUrl(url: Url):
    scanResults = analyzeUrl(url.url)
    print(scanResults)
    return scanResults

# The API offeres a lot of data we can use for now we will focus on the if it returns True or False if a site is malicious
if __name__ == "__main__": uvicorn.run(app, host="127.0.0.1", port=5050)


