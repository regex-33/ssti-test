import subprocess
from colorama import Fore, Style
import requests
import argparse
import concurrent.futures
import time
import base64
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

output_file = "result.txt"
payloads = []
urls = []
vulnerability_pattern = ""
headers = []
method = "GET"
proxy = ""
delay = 0
concurrency = 20
silent = False
timeout = 20


def print_help():
    print("Usage: python3 script.py -p <payload_file> -l <url_file> [-H <header>] [-m <method>] [--proxy <proxy>] [-d <delay>] [-c <concurrency>] [-t <timeout>] [-q] [-h]")
    print("Options:")
    print("-p, --payload-file <payload_file>   Specify the file containing payloads (required)")
    print("-l, --url-file <url_file>           Specify the file containing URLs (required)")
    print("-H, --header <header>               Specify the header value (can be used multiple times)")
    print("-m, --method <method>               Specify the HTTP method (default: GET)")
    print("--proxy <proxy>                     Specify the proxy to use")
    print("-d, --delay <delay>                 Specify the delay between issuing requests in milliseconds (default: 0)")
    print("-c, --concurrency <concurrency>     Set the concurrency level (default: 20)")
    print("-t, --timeout <timeout>             Set the timeout for each request in seconds (default: 20)")
    print("-q, --silent                        Silent mode: print only vulnerable URLs")
    print("-h, --help                          Show help")

def execute_prmreplace(url, payload):
    command = f'echo "{url}" | python3 ~/my_tool/prmreplace/prmreplace.py "{payload}"'
    process = os.popen(command)
    output = process.read().strip()
    process.close()
    return output

def decode_base64(text):
    try:
        decoded_text = base64.b64decode(text).decode("utf-8")
        return decoded_text
    except:
        return None

def test_vulnerability(host):
    headers_dict = {header.split(":")[0]: header.split(":")[1].strip() for header in headers}
    proxies = {"http": proxy, "https": proxy} if proxy else None

    try:
        if method == "GET":
            response = requests.get(host, headers=headers_dict, verify=False, proxies=proxies, timeout=timeout)
        else:
            response = requests.post(host, headers=headers_dict, verify=False, proxies=proxies, timeout=timeout)

        if vulnerability_pattern == "ssti":
            if "49" in response.text or "7777777" in response.text:
                if not silent:
                    print(f"{Fore.RED}{host} Vulnerable{Style.RESET_ALL}")
            elif not silent:
                print(f"{Fore.GREEN}{host} Not vulnerable{Style.RESET_ALL}")

        elif vulnerability_pattern == "sqlerror":
            if "syntax" in response.text.lower() or "mysql" in response.text.lower():
                if not silent:
                    print(f"{Fore.RED}{host} Vulnerable{Style.RESET_ALL}")
            elif not silent:
                print(f"{Fore.GREEN}{host} Not vulnerable{Style.RESET_ALL}")

        time.sleep(delay / 1000)

    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.Timeout):
            if not silent:
                print(f"{Fore.RED}{host} Timeout: {str(e)}{Style.RESET_ALL}")
        else:
            if not silent:
                print(f"{Fore.RED}{host} Error: {str(e)}{Style.RESET_ALL}")

def main():
    global output_file, payloads, urls, headers, method, proxy, delay, concurrency, silent, vulnerability_pattern, timeout

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--payload-file", dest="payload_file", help="Specify the file containing payloads", required=True)
    parser.add_argument("-l", "--url-file", dest="url_file", help="Specify the file containing URLs", required=True)
    parser.add_argument("-H", "--header", dest="headers", help="Specify the header value", action="append")
    parser.add_argument("-m", "--method", dest="method", help="Specify the HTTP method", default="GET")
    parser.add_argument("--proxy", dest="proxy", help="Specify the proxy to use")
    parser.add_argument("-d", "--delay", dest="delay", help="Specify the delay between issuing requests in milliseconds", type=int, default=0)
    parser.add_argument("-c", "--concurrency", dest="concurrency", help="Set the concurrency level", type=int, default=20)
    parser.add_argument("-t", "--timeout", dest="timeout", help="Set the timeout for each request in seconds", type=int, default=20)
    parser.add_argument("-q", "--silent", dest="silent", help="Silent mode: print only vulnerable URLs", action="store_true")
    args = parser.parse_args()

    payload_file = args.payload_file
    url_file = args.url_file
    headers = args.headers or []
    method = args.method.upper()
    proxy = args.proxy
    delay = args.delay
    concurrency = args.concurrency
    silent = args.silent
    timeout = args.timeout

    if not payload_file or not url_file:
        print("Please specify both payload and URL files")
        exit(1)

    print("Choose vulnerability type:")
    print("1- Server-Side Template Injection (SSTI)")
    print("2- SQL Error")
    vulnerability_choice = input("Enter your choice: ")

    if vulnerability_choice == "1":
        vulnerability_pattern = "ssti"
    elif vulnerability_choice == "2":
        vulnerability_pattern = "sqlerror"
    else:
        print("Invalid vulnerability choice")
        exit(1)

    try:
        with open(payload_file, "r") as f:
            payloads = f.read().splitlines()

        with open(url_file, "r") as f:
            urls = f.read().splitlines()

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            with open("results.txt", "w") as output_file:
                for payload in payloads:
                    for url in urls:
                        new_url = execute_prmreplace(url, payload)
                        output_file.write(new_url + "\n")

        print(Fore.YELLOW + "NOW I TRY TO FIND ANY BUG" + Style.RESET_ALL)

        # Check response for each URL in results.txt using concurrency
        with open("results.txt", "r") as result_file:
            urls = result_file.read().splitlines()

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            # Create a list of futures
            futures = [executor.submit(test_vulnerability, url) for url in urls]

            # Wait for all futures to complete
            concurrent.futures.wait(futures)

    except FileNotFoundError as e:
        print(f"File not found: {e.filename}")
        exit(1)

if __name__ == "__main__":
    main()
