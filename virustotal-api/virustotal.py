import requests
import os
import codecs
from dotenv import load_dotenv
import json 
import httpx

# Allows us to use Enviroment Varibles
load_dotenv()
apiKey = os.getenv("TOTALVIRUS_KEY") # CALLS THE TOKEN ENVIRONMENT
AccountID = os.getenv("ACCOUNT_ID_VIRUSTOTAL")

#this just read the txt to compare
with open('virustester.txt', 'rb') as fp:
    v = fp.read()

    print(f'\n \n \n \n ', { v }, '\n \n \n \n' )



zipPassword = '' #potential password for zips



filetest = { "file": ('virustester.txt', open('virustester.txt', "rb"), "") } 



# payload = { "password": zipPassword } #IF THE FILE HAS A PASSWORD IT WOULD PROCESS HERE)?


# headers = {
#     "x-apikey": apiKey,
#     "accept": "application/json",
    
# }


#  #response = requests.post(url, files=files, headers=headers)

# print(response.text)

# print(response)


def analyzeFile(files):

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

    data = r.json()


    print(f'THIS IS THE ANALYSIS KEY!!!!: ', {data["data"]["id"]})

  


    
analyzeFile(filetest)




