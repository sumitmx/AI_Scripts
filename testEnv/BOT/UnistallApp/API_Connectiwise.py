import requests
import base64

company_id = "managedsolution"
public_key = "i2FBENkfQvDJkpIn"
private_key = "JogkuwDQ5fYQLbcv"
client_id = "ffb598f7-47ab-4423-9c58-9d07341576a0"
ticket_id = 1904442
api_base_url = "https://cw.managedsolution.com/v4_6_release/apis/3.0"

credentials = f"{company_id}+{public_key}:{private_key}"
encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

headers = {
    "Authorization": f"Basic {encoded_credentials}",
    "clientId": client_id,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

endpoint = f"service/tickets/{ticket_id}/notes"

url = f"{api_base_url}/{endpoint}"
response = requests.get(url, headers=headers)
import json

if response.status_code == 200:
    notes = response.json()
    print(notes[0]['text'])
    print(f"Found {len(notes)} notes for ticket {ticket_id}:")
    for note in notes:
        print(f"Note ID: {note['id']}")
        # print(f"Date: {note.get('dateEntered')} | Text: {note['text']}")
        # print()
else:
    print(f"Error {response.status_code}")
    print(response.json)