import argparse
import asyncio
import aiohttp
import os
import time
import logging
import json
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qs
from colorama import Fore, init, Style
from tqdm import tqdm
import requests  


init(autoreset=True)


logging.basicConfig(level=logging.CRITICAL)
aiohttp_logger = logging.getLogger('aiohttp')
aiohttp_logger.setLevel(logging.CRITICAL)

banner = f"""
{Fore.GREEN}{Style.BRIGHT}
  _______                ____                  __
 /_  __(_)___ ___  ___  / __ )________  ____ _/ /_____  _____
  / / / / __ `__ \/ _ \/ __  / ___/ _ \/ __ `/ //_/ _ \/ ___/
 / / / / / / / / /  __/ /_/ / /  /  __/ /_/ / ,< /  __/ /    
/_/ /_/_/ /_/ /_/\___/_____/_/   \___/\__,_/_/|_|\___/_/     


      🕒 TimeBreaker by GR33NSLIM3 🕒
{Style.RESET_ALL}
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_file_path(prompt_text):
    return input(prompt_text).strip()

def read_lines_from_file(file_path):
    try:
        with open(file_path) as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading file: {file_path}. Exception: {str(e)}")
        exit(1)

def read_headers_from_file(headers_file):
    try:
        with open(headers_file) as file:
            headers = json.load(file)
            return headers
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading headers file: {headers_file}. Exception: {str(e)}")
        exit(1)

def send_to_discord(webhook_url, url, payload):
    try:
        data = {
            "content": f"💉 Vulnerable to SQLi 💉\n\nURL: {url}\nPayload: {payload}"
        }
        response = requests.post(webhook_url, json=data)
        if response.status_code == 204:
            print(f"{Fore.GREEN}[+] Sent to Discord: {url} | Payload: {payload}")
        else:
            print(f"{Fore.RED}[!] Failed to send to Discord. Status Code: {response.status_code}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error sending to Discord: {str(e)}")

class TimeBasedSQLiScanner:
    def __init__(self, urls, payloads, output_file, concurrency, timeout, delay, min_response_time, max_response_time, verbose, headers, webhook_url=None):
        self.urls = urls
        self.payloads = payloads
        self.output_file = output_file
        self.concurrency = concurrency
        self.timeout = timeout
        self.delay = delay
        self.min_response_time = min_response_time
        self.max_response_time = max_response_time
        self.verbose = verbose
        self.vulnerable_urls = []  
        self.total_scanned = 0
        self.headers = headers
        self.webhook_url = webhook_url

    def generate_payload_urls(self, url, payload):
        url_combinations = []
        try:
            scheme, netloc, path, query_string, fragment = urlsplit(url)
            if not scheme:
                scheme = 'http'
            query_params = parse_qs(query_string, keep_blank_values=True)
            for key in query_params.keys():
                modified_params = query_params.copy()
                modified_params[key] = [payload]
                modified_query_string = urlencode(modified_params, doseq=True)
                modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
                url_combinations.append(modified_url)
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error generating payload URL for {url} with payload {payload}: {str(e)}")
        return url_combinations

    async def fetch(self, sem, session, url, payload):
        async with sem:
            try:
                start_time = time.time()
                if self.verbose:
                    print(f"{Fore.CYAN}[i] Scanning {url} with payload: {payload}")
                async with session.get(url, headers=self.headers, allow_redirects=True, timeout=self.max_response_time) as resp:
                    response_time = time.time() - start_time
                    if response_time >= self.min_response_time:
                        if response_time >= self.delay:
                            print(f"{Fore.GREEN}💉 Potential Vulnerability: {Fore.WHITE}{url}")
                            return (url, payload)  
            except asyncio.TimeoutError:
                if self.verbose:
                    print(f"{Fore.RED}[!] Timeout fetching {url}. Skipping to next URL.")
                return 'timeout'
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Error fetching {url}: {str(e)}")
                return 'error'

    async def double_check(self, sem, session, url, payload):
        """Double check the potential vulnerability by testing again."""
        result = await self.fetch(sem, session, url, payload)
        return result

    async def scan(self):
        sem = asyncio.Semaphore(self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            total_tasks = len(self.urls)
            with tqdm(total=total_tasks, desc="Scanning URLs", unit="url") as pbar:
                for url in self.urls:
                    url_vulnerable = False
                    for payload in self.payloads:
                        urls_with_payload = self.generate_payload_urls(url.strip(), payload)
                        tasks = [self.fetch(sem, session, payload_url, payload) for payload_url in urls_with_payload]
                        results = await asyncio.gather(*tasks)

                        if 'timeout' in results or 'error' in results:
                            if self.verbose:
                                print(f"{Fore.YELLOW}[i] Skipping {url} due to error or timeout.")
                            break

                       
                        found_vulnerable = [result for result in results if isinstance(result, tuple)]
                        if found_vulnerable:
                            
                            double_check_tasks = [self.double_check(sem, session, result[0], result[1]) for result in found_vulnerable]
                            double_check_results = await asyncio.gather(*double_check_tasks)

                            
                            confirmed_vulnerable = [result for result in double_check_results if isinstance(result, tuple)]
                            if confirmed_vulnerable:
                                self.vulnerable_urls.extend(confirmed_vulnerable)
                                self.total_scanned += 1
                                url_vulnerable = True
                              
                                if self.webhook_url:
                                    for vuln in confirmed_vulnerable:
                                        send_to_discord(self.webhook_url, vuln[0], vuln[1])
                                break

                    if self.verbose and not url_vulnerable:
                        print(f"{Fore.YELLOW}[i] No vulnerabilities found for {url}")
                    pbar.update(1)

    def run(self):
        start_time = time.time()
        asyncio.run(self.scan())
        end_time = time.time()
        print(f"{Fore.YELLOW}[i] Scanning finished.")
        print(f"{Fore.YELLOW}[i] Total found: {len(self.vulnerable_urls)}")
        print(f"{Fore.YELLOW}[i] Total scanned: {self.total_scanned}")
        print(f"{Fore.YELLOW}[i] Time taken: {int(end_time - start_time)} seconds")

        if self.vulnerable_urls:
            save_option = input(f"{Fore.CYAN}[?] Do you want to save the vulnerable URLs and payloads to {self.output_file}? (y/n): ").strip().lower()
            if save_option == 'y':
                with open(self.output_file, "w") as file:
                    for url, payload in self.vulnerable_urls:
                        file.write(f"{url} | Payload: {payload}\n")  
                print(f"{Fore.GREEN}[+] URLs and payloads saved to {self.output_file}")
            else:
                print(f"{Fore.YELLOW}Vulnerable URLs and payloads will not be saved.")

def main():
    clear_screen()
    print(banner)  

    parser = argparse.ArgumentParser(description="Time-Based Blind SQL Injection Scanner")
    parser.add_argument('-l', '--list', required=True, help="File containing the list of URLs to scan")
    parser.add_argument('-p', '--payload', required=True, help="File containing the payloads for testing")
    parser.add_argument('-o', '--output', default="output.txt", help="File to save the vulnerable URLs")
    parser.add_argument('-c', '--concurrency', type=int, default=10, help="Number of concurrent requests")
    parser.add_argument('-t', '--timeout', type=int, default=30, help="Request timeout in seconds")
    parser.add_argument('-d', '--delay', type=float, default=5.0, help="Delay in seconds to consider as a sign of vulnerability")
    parser.add_argument('-n', '--min-response-time', type=float, default=1.0, help="Minimum response time in seconds to consider as a sign of vulnerability")
    parser.add_argument('-m', '--max-response-time', type=int, default=20, help="Maximum response time in seconds before skipping the URL")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('--headers', help="File containing custom headers in JSON format")
    parser.add_argument('--webhook', help="Discord webhook URL for sending alerts")

    args = parser.parse_args()

    urls = read_lines_from_file(args.list)
    payloads = read_lines_from_file(args.payload)
    output_file = args.output
    concurrency = args.concurrency
    timeout = args.timeout
    delay = args.delay
    min_response_time = args.min_response_time
    max_response_time = args.max_response_time
    verbose = args.verbose

    headers = {}
    if args.headers:
        headers = read_headers_from_file(args.headers)

    webhook_url = args.webhook

    scanner = TimeBasedSQLiScanner(urls, payloads, output_file, concurrency, timeout, delay, min_response_time, max_response_time, verbose, headers, webhook_url)
    scanner.run()

if __name__ == "__main__":
    main()
