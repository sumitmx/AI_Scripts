from cw_rpa import Logger, Input, HttpClient
import re

log = Logger()

class CWPSAClient:
    """Client for making requests to the ConnectWise PSA API."""
    
    def __init__(self):
        self.http_client = HttpClient()
        self.client = self.http_client.third_party_integration("cw_psa")
        self.base_url = "https://cw.managedsolution.com/v4_6_release/apis/3.0"

    def get_configurations(self, endpoint: str) -> list:
        """Fetch configurations from the specified CW endpoint."""
        try:
            full_url = f"{self.base_url}/{endpoint}"
            response = self.client.get(url=full_url)
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            log.error(f"Error fetching configurations: {str(e)}")
            return []

def check_words(input_string):
    """Check for specific keywords in the input string."""
    keywords = ["Shift Browser", "Wave Browser", "PCAppStore", "OneStart","OneLaunch"]
    lower_input = input_string.lower()

    keyword_list = []
    
    for keyword in keywords:
        if keyword.lower() in lower_input:
            log.info(f"Keyword found: {keyword}")
            keyword_list.append(keyword)
    
    if keyword_list:
        return keyword_list
    else:
        log.info("No keywords found in the input string.")
        return "Not found"

def extract_machine_code(input_string):
    # pattern = r'We have detected a new threat on (\w+-\w+) in the group'
    # match = re.search(pattern, input_string)
    # if match:
    #     return match.group(1).strip()
    # else:
    #     return "Not found"
    pattern = [
                r'We have detected a new threat on (\w+-\w+) in the group', 
                r'winlog\.computer_name:\s*([\w.-]+)',
                r'Affected Endpoints:\s*([a-zA-Z0-9\-]+)',
                r'Endpoint:\s*([A-Z0-9\-]+)'
              ]

    for i in pattern:
        match = re.search(i, input_string)
        if match:
            return match.group(1).split(".")[0]
        else:
            continue

def return_appname_machineName():
    input = Input()

    try:
        log.info("Bot started")
        

        # ticket_num = input.get_value("TicketNumber_1739388501152")
        # ticket_num = ticket_num.split(" ")[2].strip()
        # log.info(f"Ticket number retrieved: {ticket_num}")

        # log.info("Starting CW PSA Client")
        # client = CWPSAClient()


        # endpoint = f"service/tickets/{ticket_num}/notes"
        

        # items = client.get_configurations(endpoint)
        
        # if items:
        #     text = items[0].get('text', 'No text available')
        #     # machinename = extract_machine_code(text)
        #     log.info(f"First item text: {text}")
        #     result = check_words(text)
        #     log.result_success_message(f"Successfully retrieved data: {text}")
        # else:
        #     log.info("No items found in response")
        #     log.result_success_message("Failed to retrieve any items.")
        #     return 
        text = input.get_value("TicketNumber_1739388501152")
        result = check_words(text)
        log.result_success_message(f"Successfully retrieved data: {text}")

        if result:
            machinename = extract_machine_code(text)  
            log.info(f"machine name : {machinename}")  
            log.info(f"App name({result}) found in the initial description of ticket")
            # log.result_data({
            #                     "appNameExists": result,
            #                     "machine_name" : machinename
            #                 })
            # log.result_success_message(f"App name found: {result} and machine name : {machinename}")
        else:
            log.info("App name not found in the initial description of ticket")
            # log.result_data({"appNameExists": result})

        log.info("Bot stopped")

        return()

    except Exception as e:
        log.exception(f"Exception found: {e}", stack_info=True)




def main():
    input = Input()

    try:
        log.info("Bot started")
        

        # ticket_num = input.get_value("TicketNumber_1739388501152")
        # ticket_num = ticket_num.split(" ")[2].strip()
        # log.info(f"Ticket number retrieved: {ticket_num}")

        # log.info("Starting CW PSA Client")
        # client = CWPSAClient()


        # endpoint = f"service/tickets/{ticket_num}/notes"
        

        # items = client.get_configurations(endpoint)
        
        # if items:
        #     text = items[0].get('text', 'No text available')
        #     # machinename = extract_machine_code(text)
        #     log.info(f"First item text: {text}")
        #     result = check_words(text)
        #     log.result_success_message(f"Successfully retrieved data: {text}")
        # else:
        #     log.info("No items found in response")
        #     log.result_success_message("Failed to retrieve any items.")
        #     return 
        text = input.get_value("TicketNumber_1739388501152")
        result = check_words(text)
        log.result_success_message(f"Successfully retrieved data: {text}")

        if result:
            machinename = extract_machine_code(text)  
            log.info(f"machine name : {machinename}")  
            log.info(f"App name({result}) found in the initial description of ticket")
            log.result_data({
                                "appNameExists": result,
                                "machine_name" : machinename
                            })
            log.result_success_message(f"App name found: {result} and machine name : {machinename}")
        else:
            log.info("App name not found in the initial description of ticket")
            log.result_data({"appNameExists": result})

        log.info("Bot stopped")

    except Exception as e:
        log.exception(f"Exception found: {e}", stack_info=True)

if __name__ == "__main__":
    main()