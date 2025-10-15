import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from pprint import pprint

def get_forms(url):
    """Given a URL, it returns all forms from the HTML content"""
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    """
    Submits a form given in `form_details`
    Params:
        form_details (dict): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced for all text and search inputs
    Returns the HTTP Response after form submission
    """
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def run_xss_scanner(url):
    """
    Given a `url`, it prints all XSS vulnerable forms and
    returns True if any is vulnerable, False otherwise
    """
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<script>alert('hi')</script>"
    is_vulnerable = False
    for form in forms:
        form_details = form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
    return is_vulnerable
