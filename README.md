# **Smart 403 Bypass Toolkit 🕵️‍♂️🔓**

## **Overview**

The **Smart 403 Bypass Toolkit** is an advanced and intelligent Python-based tool designed to help penetration testers and bug bounty hunters discover ways to bypass 403 Forbidden responses on web applications. Leveraging a wide array of HTTP method, path, and header manipulations, this toolkit aims to uncover misconfigurations and vulnerabilities that allow access to restricted resources.  
Unlike simpler tools, this toolkit employs asynchronous requests for speed and features intelligent detection logic that goes beyond just checking for 200 OK responses, considering redirects and significant content length changes as potential bypasses.

## **Features**

* **Extensive Bypass Techniques:** Implements a broad range of HTTP method, path, and header manipulations.  
* **Asynchronous Requests:** Built with httpx and asyncio for high-performance, concurrent scanning.  
* **Intelligent Detection:**  
  * Identifies 2xx success codes.  
  * Detects 3xx redirects that differ from the original 403 response.  
  * Recognizes status codes other than 403 (e.g., 401, 500\) as potential bypasses of the initial 403\.  
  * Flags significant content length changes (more than 10% difference from the original) as a bypass indicator.  
* **Customization:** Allows users to define custom headers and cookies for authenticated or specific tests.  
* **Proxy Support:** Seamlessly integrates with HTTP/S proxies like Burp Suite or ZAP.  
* **SSL Verification Control:** Option to disable SSL certificate verification.  
* **Redirect Control:** Option to disable automatic following of HTTP redirects.  
* **Verbose Output:** Provides detailed output for every request attempt, useful for debugging and analysis.  
* **Clear Reporting:** Presents successful bypasses with comprehensive details including URL, method, headers, status code, content length, and the technique used.

## **Installation**

1. **Clone the repository:**  
   ```bash
   git clone https://github.com/battouachraf/Smart-403-Bypass-Toolkit.git  
   cd Smart-403-Bypass-Toolkit
   ```

2. **Install dependencies:**  
   ```bash
   pip install -r requirements.txt
   ```

## **Usage**

Run the script from your terminal:  
```bash
python smart_403_bypass.py -u <TARGET_URL> [OPTIONS]
```

### **Arguments:**

* -u, --url **(Required)**: The target URL to test for 403 bypass (e.g., https://example.com/admin).  
* -p, --proxy: HTTP/S proxy to use (e.g., http://127.0.0.1:8080).  
* -t, --timeout: Request timeout in seconds (default: 10).  
* --no-ssl-verify: Disable SSL certificate verification.  
* -c, --cookies: Cookies to send (e.g., 'session=abc; auth=xyz'). Use quotes for multiple cookies.  
* -H, --header: Add a custom header (e.g., 'Authorization: Bearer token'). Can be used multiple times.  
* --no-redirects: Do not follow HTTP redirects.  
* -v, --verbose: Enable verbose output for all attempts.

### **Examples:**

1. **Basic scan:**  
   ```bash
   python smart_403_bypass.py -u https://target.com/admin
   ```

2. **Scan with Burp Suite proxy:**  
   ```bash
   python smart_403_bypass.py -u https://target.com/admin -p http://127.0.0.1:8080
   ```

3. **Scan with custom headers and cookies:**  
   ```bash
   python smart_403_bypass.py -u https://target.com/admin -H "X-Custom-Auth: secretkey" -H "Referer: https://internal.app" -c "session_id=abcdef123; user=admin"
   ```

4. **Verbose scan with disabled SSL verification:**  
   ```bash
   python smart_403_bypass.py -u https://target.com/api/v1/users --no-ssl-verify -v
   ```

## **Bypass Techniques Covered**

The toolkit attempts bypasses using a combination of the following techniques:

### **HTTP Method Manipulation:**

* HEAD  
* POST  
* PUT  
* PATCH  
* OPTIONS  
* TRACE  
* CONNECT  
* PROPFIND

### **Path Manipulation:**

* Trailing slashes (/path/)  
* Dots (/path/.)  
* Encoded dots (/path/%2e, /path/%252e)  
* Semicolon trick (/path/;/)  
* Double slashes (//path)  
* Encoded slashes (%2f, %252f)  
* Unicode encoded characters (%u002f, %u002e)  
* Null bytes (%00)  
* Tab characters (%09)  
* Appending common file extensions (.json, .html, .php, .js, etc.)  
* Appending empty query strings (?)  
* Appending fragment identifiers (\#)  
* Dot-dot-slash variations (..%2f, %2f..)  
* Adding common empty query parameters (?id=, ?file=, etc.)

### **Header Manipulation:**

* X-Original-URL  
* X-Rewrite-URL
* X-Proxy-URL  
* X-Forwarded-For (with common internal IPs like 127.0.0.1, localhost)  
* X-Real-IP  
* X-Custom-IP-Authorization  
* Referer (pointing to /admin or external sites)  
* Host header manipulation (e.g., localhost, target.com:8080)  
* Content-Type variations (for POST requests, with empty/simple JSON/form bodies)  
* Origin header (null or target domain)  
* Accept: \*/\*  
* User-Agent rotation (though currently defaults to one, easily expandable)

## **Contributing**

Contributions are welcome\! If you have ideas for new bypass techniques, improvements to existing ones, or bug fixes, please open an issue or submit a pull request.

## **License**

This project is licensed under the MIT License \- see the LICENSE file for details.

## **Disclaimer**

This tool is intended for **ethical hacking and educational purposes only**. Use it responsibly and only on systems you have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool. Always comply with applicable laws and the terms of service of any platform you are testing.
