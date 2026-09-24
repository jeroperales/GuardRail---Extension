import requests
import os
import codecs
from dotenv import load_dotenv


# Allows us to use Enviroment Varibles
load_dotenv()
apiKey = os.getenv("TOTALVIRUS_KEY") # CALLS THE TOKEN ENVIRONMENT
AccountID = os.getenv("ACCOUNT_ID_VIRUSTOTAL")



with open('virustester.txt', 'rb') as fp:
    v = fp.read()

    print(f'\n \n \n \n ', { v }, '\n \n \n \n' )



zipPassword = '' #potential password for zips




#print (f'THIS IS THE API KEY BROTHER', {apiKey})


url = "https://www.virustotal.com/api/v3/files"


files = { "file": ('virustester.txt', open('virustester.txt', "rb"), "") } 



payload = { "password": zipPassword } #IF THE FILE HAS A PASSWORD IT WOULD PROCESS HERE)?


headers = {
    "x-apikey": apiKey,
    "accept": "application/json",
    
}

response = requests.post(url, files=files, headers=headers)

print(response.text)



