from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    result = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115 Safari/537.36'
    }

    try:
        # Main page request
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        result['status'] = f"Status Code: {response.status_code}"

        # XSS detection
        xss_indicators = ['<script>', 'onerror=', 'onload=', 'alert(', 'document.cookie', 'javascript:', 'vbscript:', 'onmouseover=', 'onfocus=']
        xss_found = any(indicator in response.text.lower() for indicator in xss_indicators)
        
        # Check for reflected XSS by testing with payload
        xss_payload = '<script>alert(1)</script>'
        try:
            test_response = requests.get(f"{url}?test={xss_payload}", headers=headers, timeout=5, verify=False)
            if xss_payload in test_response.text:
                xss_found = True
        except:
            pass
            
        result['xss'] = "XSS vulnerability detected" if xss_found else "No XSS vulnerability found"

        # Clickjacking protection check
        frame_option = response.headers.get('X-Frame-Options')
        csp = response.headers.get('Content-Security-Policy', '')
        if 'frame-ancestors' in csp or frame_option:
            result['clickjacking'] = "Protected from clickjacking"
        else:
            result['clickjacking'] = "Vulnerable to clickjacking"

        # SQL Injection detection
        sqli_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT NULL--"]
        sqli_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db', 'odbc', 'sqlite_exception']
        sqli_found = False
        
        for payload in sqli_payloads:
            try:
                test_resp = requests.get(f"{url}?id={payload}", headers=headers, timeout=5, verify=False)
                if any(error in test_resp.text.lower() for error in sqli_errors):
                    sqli_found = True
                    break
            except:
                continue
                
        result['sqli'] = "SQL Injection vulnerability detected" if sqli_found else "No SQL Injection vulnerability found"

        # Authentication and Session Management
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        auth_issues = []
        
        # Check for login forms
        login_forms = [f for f in forms if any(field in str(f).lower() for field in ['password', 'login', 'signin'])]
        if login_forms:
            auth_issues.append("Login form found - verify secure authentication")
            
        # Check session cookies
        cookies = response.cookies
        for cookie in cookies:
            if not cookie.secure:
                auth_issues.append(f"Insecure cookie: {cookie.name}")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                auth_issues.append(f"Cookie missing HttpOnly: {cookie.name}")
                
        result['auth'] = auth_issues if auth_issues else ["No authentication issues detected"]

        # Security Misconfiguration check
        misconfig_flags = []
        
        # Server information disclosure
        if response.headers.get('Server'):
            misconfig_flags.append(f"Server header exposed: {response.headers['Server']}")
        if response.headers.get('X-Powered-By'):
            misconfig_flags.append(f"Technology disclosure: {response.headers['X-Powered-By']}")
            
        # Directory listing
        if "index of /" in response.text.lower():
            misconfig_flags.append("Directory listing enabled")
            
        # Error handling
        error_indicators = ['exception', 'stack trace', 'error occurred', 'warning:', 'fatal error']
        if any(error in response.text.lower() for error in error_indicators):
            misconfig_flags.append("Verbose error messages detected")
            
        # Default pages
        default_indicators = ['welcome to', 'default page', 'it works', 'apache2 ubuntu']
        if any(default in response.text.lower() for default in default_indicators):
            misconfig_flags.append("Default web server page detected")

        result['misconfig'] = misconfig_flags if misconfig_flags else ["No security misconfigurations found"]

        # Security headers
        result['headers'] = {
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Missing'),
            'Content-Security-Policy': csp if csp else 'Missing',
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Missing'),
            'Referrer-Policy': response.headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': response.headers.get('Permissions-Policy', 'Missing'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Missing')
        }

    except requests.exceptions.SSLError as ssl_error:
        result['error'] = f"SSL error: {str(ssl_error)}"
    except requests.exceptions.RequestException as req_error:
        result['error'] = f"Request error: {str(req_error)}"
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"

    return render_template('result.html', result=result, url=url)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
