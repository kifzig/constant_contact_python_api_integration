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
import json

driverService = Service('C:/Users/Kif/Desktop/chromedriver_win32/chromedriver.exe')
driver = webdriver.Chrome(service=driverService)

CLIENT_ID_API_KEY = config('CLIENT_ID')
CLIENT_SECRET = config('CLIENT_SECRET')
REDIRECT_URL = config('REDIRECT_URL')
CC_EMAIL = config('EMAIL')
CC_PASSWORD = config('PASSWORD')

URL = "https://api.cc.email/v3/contacts"
STATE = "l123okdsk1kl"
SCOPE = "contact_data"

response = requests.get(URL, )

#This application sends GET requests to https://authz.constantcontact.com/oauth2/default/v1/authorize to initiate authorization requests.
#This application sends POST requests to https://authz.constantcontact.com/oauth2/default/v1/token to exchange authorization codes for bearer tokens.
#It follows the outline of authentication details below on the Constant Contact API guide:

#OAuth2 Authorization Code Flow
#https://v3.developer.constantcontact.com/api_guide/server_flow.html

#https://api.cc.email/v3/contacts?status=all&include_count=true&limit=50
#https://api.cc.email/v3/contact_lists/{list_id}

def getAuthorizationURL():
    baseURL = "https://authz.constantcontact.com/oauth2/default/v1/authorize"
    authURL = baseURL + "?client_id=" + CLIENT_ID_API_KEY + "&scope=" + SCOPE + "+offline_access&response_type=code&redirect_uri=" + REDIRECT_URL + "&state=" + STATE
    print(authURL)
    print(type(authURL))
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
    print(f"Encoded string: {auth_base64_string}")


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
    headers = {"Content-type": "application/x-www-form-urlencoded",
               "Accept": "application/json",
                "Authorization" : bearer_token}
    return headers


#Step 1: Create an authorization request
authURL = getAuthorizationURL()
# response = requests.get(authURL)

response = requests.get(authURL)
if response.history:
    print("Request was redirected.")
    for resp in response.history:
        print(resp.status_code, "URL: ",  resp.url)
    print("Final destination: ")
    print(response.status_code, response.url)
    url = response.url
    driver.maximize_window()
    driver.get(url)
    username = driver.find_element(By.ID, "okta-signin-username").send_keys(CC_EMAIL + Keys.TAB)
    password = driver.find_element(By.ID, "okta-signin-password").send_keys(CC_PASSWORD + Keys.ENTER)
    time.sleep(10)

    #Get the authorization code
    url_with_code = driver.current_url
    print(url_with_code)
    code = parse_code_from_URL(url_with_code)
    state = parse_state_from_URL(url_with_code)
    print(f"code: {code}  -  state: {state}")

    token_header = get_authorization_token_header(get_access_token(code))
    print(token_header)

    ##Get User Privileges - 1st API Request GET
    # user_priv_URL = "https://api.cc.email/v3/account/user/privileges"
    # r = requests.get(user_priv_URL, headers=token_header)
    # print("API - GET USER PRIVILEGES")
    # print(r.text)
    #
    # #Get Summary of Account Details
    # account_summary_url = 'https://api.cc.email/v3/account/summary'
    # r = requests.get(account_summary_url, headers=token_header)
    # print('ACCOUNT SUMMARY DETAILS')
    # print(r.text)

    #Create a contact list - Scope is contact_data
    list_input = {"name": "Delete this List",
                  "favorite": False,
                  "description": "Constant Contant API List Test"}
    create_list_URL = "https://api.cc.email/v3/contact_lists"
    r = requests.post(url=create_list_URL, params=list_input, headers=token_header)
    r_json = json.loads(r.text)
    new_list_id = r_json.get("list_id")
    print(f"list id = {new_list_id}")

    #Delete a contact list
    del_list_url = f'https://api.cc.email/v3/contact_lists/{new_list_id}'
    r_del = requests.delete(del_list_url, headers=token_header)
    print(r_del.text)



else:
    print("Request was not redirected.")


