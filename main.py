import requests
import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from urllib.parse import urlparse
from urllib.parse import parse_qs
from decouple import config

import base64

SCOPE = "campaign_data" #will change depending on call - notice scope in api docs
STATE = "l123okdsk1kl" #state is arbitrary

#chromedriver.exe downloaded to use Selenium - stored locally
driverService = Service('C:/Users/Kif/Desktop/chromedriver_win32/chromedriver.exe')
driver = webdriver.Chrome(service=driverService)

#This information is from constantcontact.com - you must register the application for a key and client secret
#https://v3.developer.constantcontact.com/api_guide/getting_started.html
CLIENT_ID_API_KEY = config('CLIENT_ID')
CLIENT_SECRET = config('CLIENT_SECRET')
REDIRECT_URL = config('REDIRECT_URL')
CC_EMAIL = config('EMAIL') #Email used to login to constantcontact.com
CC_PASSWORD = config('PASSWORD') #Password used for constantcontact.com





#This application sends GET requests to https://authz.constantcontact.com/oauth2/default/v1/authorize to initiate authorization requests.
#This application sends POST requests to https://authz.constantcontact.com/oauth2/default/v1/token to exchange authorization codes for bearer tokens.
#It follows the outline of authentication details below on the Constant Contact API guide:

#OAuth2 Authorization Code Flow
#https://v3.developer.constantcontact.com/api_guide/server_flow.html

def getAuthorizationURL():
    baseURL = "https://authz.constantcontact.com/oauth2/default/v1/authorize"
    authURL = baseURL + "?client_id=" + CLIENT_ID_API_KEY + "&scope=" + SCOPE + "+offline_access&response_type=code&redirect_uri=" + REDIRECT_URL + "&state=" + STATE
    #print(authURL)
    #print(type(authURL))
    return(authURL)


def parse_code_from_URL(returned_url):
    parsed_url = urlparse(returned_url)
    code = parse_qs(parsed_url.query)['code'][0]
    return(code)


def parse_state_from_URL(returned_url):
    parsed_url = urlparse(returned_url)
    state = parse_qs(parsed_url.query)['state'][0]
    return(state)

def get_access_token(code):
    #create request URL
    baseURL = "https://authz.constantcontact.com/oauth2/default/v1/token"

    #Base64 Encode the String client_id:client_secret for Authorization header
    auth_string = CLIENT_ID_API_KEY + ":" + CLIENT_SECRET
    auth_string_bytes = auth_string.encode("ascii")
    auth_base64_bytes = base64.b64encode(auth_string_bytes)
    auth_base64_string = auth_base64_bytes.decode("ascii")
    #print(f"Encoded string: {auth_base64_string}")

    headers = {"Content-type": "application/x-www-form-urlencoded",
               "Accept": "application/json",
               "Authorization": "Basic " + auth_base64_string}
    params = {"code": code,
              "redirect_uri": REDIRECT_URL,
              "grant_type": "authorization_code"} #required -- always authorization_code
    r = requests.post(baseURL, headers=headers, params=params)
    json_token_info = r.text
    json_token_info = eval(json_token_info) #converts string to json
    return json_token_info.get("access_token")

def get_authorization_token_header(access_token):
    bearer_token = "Bearer " + access_token
    #headers = {"Content-type": "application/x-www-form-urlencoded",
    headers = {"Content-type": "application/json",
               "Accept": "application/json",
                "Authorization" : bearer_token}
    return headers


#Step 1: Create an authorization request
authURL = getAuthorizationURL()

response = requests.get(authURL)
if response.history:
    #Uncomment below for help with troubleshooting
    # print("Request was redirected.")
    # for resp in response.history:
    #     print(resp.status_code, "URL: ",  resp.url)
    # print("Final destination: ")
    # print(response.status_code, response.url)
    url = response.url
    driver.maximize_window()
    driver.get(url)
    username = driver.find_element(By.ID, "okta-signin-username").send_keys(CC_EMAIL + Keys.TAB)
    password = driver.find_element(By.ID, "okta-signin-password").send_keys(CC_PASSWORD + Keys.ENTER)
    time.sleep(7)

    #Get the authorization code
    url_with_code = driver.current_url
    code = parse_code_from_URL(url_with_code)
    state = parse_state_from_URL(url_with_code)

    token_header = get_authorization_token_header(get_access_token(code))
    driver.quit()
    #print(token_header)


    ##Get User Privileges - 1st API Request GET - These work, but need to be uncommented
    # user_priv_URL = "https://api.cc.email/v3/account/user/privileges"
    # r = requests.get(user_priv_URL, headers=token_header)
    # print("API - GET USER PRIVILEGES")
    # print(r.text)
    # #
    # #Get Summary of Account Details
    # account_summary_url = 'https://api.cc.email/v3/account/summary'
    # r = requests.get(account_summary_url, headers=token_header)
    # print('ACCOUNT SUMMARY DETAILS')
    # print(r.text)

    #Create a contact list - Scope is contact_data
    # list_input = {"name": "Delete this List",
    #               "favorite": False,
    #               "description": "Constant Contant API List Test"}
    # create_list_URL = "https://api.cc.email/v3/contact_lists"
    # r = requests.post(url=create_list_URL, params=list_input, headers=token_header)
    # r_json = json.loads(r.text)
    # new_list_id = r_json.get("list_id")
    # #print(f"list id = {new_list_id}")
    #
    # #Delete a contact list - Deletes the list made above
    # del_list_url = f'https://api.cc.email/v3/contact_lists/{new_list_id}'
    # r_del = requests.delete(del_list_url, headers=token_header)
    # #print(r_del.text)


    #Get Contacts Collection - scope is contact_data
    # get_contacts_URL = "https://api.cc.email/v3/contacts"
    # get_contacts_response = requests.get(get_contacts_URL, headers=token_header, params={"limit": 50})
    # #print(get_contacts_response.text)

    # #Get an Email Campaigns Summary - scope is campaign_data - it works now
    # camp_id = 'db2b8531-448b-43e3-9a19-9347722fd929'
    # camp_id_unique_opens_report_url = "https://api.cc.email/v3/emails/db2b8531-448b-43e3-9a19-9347722fd929"
    # camp_response = requests.get(camp_id_unique_opens_report_url, headers=token_header)
    # print(camp_response.text)
    # print(camp_response.status_code)

    #Get a Collection of Email Campaigns
    campaigns_url = "https://api.cc.email/v3/emails"
    campaigns_list = requests.get(campaigns_url, headers=token_header)
    print(campaigns_list.text)




else:
    print("Request was not redirected.")


