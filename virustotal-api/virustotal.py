import requests
import os
from dotenv import load_dotenv


# Allows us to use Enviroment Varibles
load_dotenv()
apiKey = os.getenv("TOKENVIRUS") # CALLS THE TOKEN ENVIRONMENT
AccountID = os.getenv("ACCOUNT_ID_VIRUSTOTAL")


zipPassword = ''

print (apiKey)

url = "https://www.virustotal.com/api/v3/files"

# files = { "file": ("", open("", "rb"), "") }

payload = { "password": zipPassword } #IF THE FILE HAS A PASSWORD IT WOULD PROCESS HERE)?

headers = {
    "x-apikey": {apiKey},
    "accept": "application/json",
    "content-type": "multipart/form-data"
}

response = requests.post(url, headers=headers)



print(response.text)


