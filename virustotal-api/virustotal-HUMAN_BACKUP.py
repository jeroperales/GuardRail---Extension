import requests
import os
import codecs
from dotenv import load_dotenv
import json 
import httpx
import hashlib
import sys
from fastapi import FastAPI, UploadFile
from fastapi.responses import PlainTextResponse
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from enum import Enum
from pydantic import BaseModel



# Allows us to use Enviroment Varibles
load_dotenv()
apiKey = os.getenv("TOTALVIRUS_KEY") # CALLS THE TOKEN ENVIRONMENT
AccountID = os.getenv("ACCOUNT_ID_VIRUSTOTAL")
algorithm =  'sha256' #for hash function

app = FastAPI()

file_path = "virustester.txt" #USER WILL INPUT FILE HERE


filetest = {
    "file": (
        os.path.basename(file_path),
        open(file_path, "rb"),
        ""
    )
}


zipPassword = '' #potential password for zips

# payload = { "password": zipPassword } #IF THE FILE HAS A PASSWORD IT WOULD PROCESS HERE)?


# headers = {
#     "x-apikey": apiKey,
#     "accept": "application/json",
    
# }


#  #response = requests.post(url, files=files, headers=headers)

# print(response.text)

# print(response)


def getAnalysisID(files):

    r = httpx.post(
        url='https://www.virustotal.com/api/v3/files',
        files=files,
        headers={
            "x-apikey": apiKey,
            "accept": "application/json"
        },
        timeout=60.0
    )
    print (r.status_code)
    print(r.text)

    
    
    if r.status_code == 200:
        print('IT WORKED')
        data = r.json()
        return data["data"]["id"]
    else:
        print('Error ocurred.')
    
  


#analysisResponse = getAnalysisID(filetest)



def analyzeFile(file, file_path):

    wasFileSent, r = file_already_sent(file_path)
    
    if wasFileSent == False:
        analysisResponse = getAnalysisID(file)
        url = f'https://www.virustotal.com/api/v3/analyses/{analysisResponse}' #CONCATENATES ANALYSIS ID W/ ANALISIS RESPONSE
        r = httpx.get( url= url, headers={ "x-apikey": apiKey, "accept": "application/json" })
      
    data = r.json()

    print(f'THIS IS THE STATUS CODE: ', {r.status_code}, '\n \n')
    print(f'THIS IS THE R.TEXT: ', {r.text})

    return data



    

#https://www.geeksforgeeks.org/python/python-program-to-find-hash-of-file/
def getHash (file, algorithm='sha256'):
    hashFunc = hashlib.new(algorithm)

    with open (file, 'rb') as file:
        while chunk := file.read(8192):
            hashFunc.update(chunk)
    return hashFunc.hexdigest()

    

hashTest = getHash('virustester.txt', algorithm) 


def file_already_sent(file_path):

    #https://stackoverflow.com/questions/8384737/extract-file-name-from-path-no-matter-what-the-os-path-format
    hash = getHash(file_path, algorithm)

    url = f"https://www.virustotal.com/api/v3/files/{hash}"

    #VERIFIES IF FILE HAS ALREADY BEEN SENT
    r = httpx.get( url = url, headers={ "x-apikey": apiKey, "accept": "application/json"}, timeout=60 )
    
  
    if r.status_code == 200:
        print ('WAIT MAN, THE FILE HAS ALREADY BEEN SENT!')
        return True, r
         
    else:
            print("FILE HAS NOT BEEN SENT YET, YOUR GOOD!")
            return False, None
    

#THE BIG FUNCTION
def is_file_malicous (file, file_path):

    data = analyzeFile(file, file_path)

    


analyzeFile(filetest, file_path)




# #ONCE WE HAVE AN ANSWER WE WOULD SEND TO FRONT END HERE
# @app.post("/file/")
# async def getFile(file: UploadFile):

#     file_path = os.path.dirname(file)
#     file_name = os.path.basename(file_path)
#     print(file_name)

#     fileResults = analyzeFile(file, file_name)

#     return fileResults