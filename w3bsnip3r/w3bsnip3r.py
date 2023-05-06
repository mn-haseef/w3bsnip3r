import sys
import os
import socket
import whois
import nmap
import getpass
from bs4 import BeautifulSoup
import subprocess
# "requests" library to send a GET request to the target
import requests
#to  iterate through the href links and extract sub-paths that include the target domain by using the "urlparse" 
from urllib.parse import urlparse
from zapv2 import ZAPv2

# Define ANSI escape codes for different colors
BLACK = "\033[0;30m"
DARK_GRAY = "\033[1;30m"
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
GRAY = "\033[0;37m"
RESET = "\033[0m"



def desc():
    print('')

def info():
    print(f'''{GREEN}Options{RESET}

    [1] Information Gathering 
    [2] Find Sub Domain
    [3] Find Sub Path 
    [4] Vulnerability Scan "Nikto"
    [5] Vulnerability Scan "Zap-Proxy"
    [6] Exit
    
    ''')


def server_info():
    try:
        u = input(f"{DARK_GRAY}host - >> {RESET}")

        # get the IP address of the hostname
        ip_address = socket.gethostbyname(u)
        print(f"IP address for {u}: {ip_address}")

        # perform a WHOIS lookup on the IP address
        w = whois.whois(ip_address)
        print(f"WHOIS information:\n{w}")

        # check for root privileges
        if getpass.getuser() != 'root':
            print("TCP/IP fingerprinting (for OS scan) requires root privileges.")
            confirm = input("Do you want to run nmap as root? (y/n): ")
            if confirm.lower() == 'y':
                os.system(f"sudo nmap -O {ip_address}")
            else:
                print("OS scan skipped.")
        else:
            # perform an nmap scan to determine the server's OS and version
            nm = nmap.PortScanner()
            nm.scan(ip_address, arguments="-O")
            os_info = nm[ip_address]['osmatch'][0]
            print(f"Server OS and version: {os_info}")

    except socket.gaierror:
        print(f"Could not resolve hostname {u}")

    except KeyboardInterrupt:
        # If the user presses CTRL-C, exit the program
        print("Exiting program")
        exit()


def find_subdomains():
    domain = input(f"{DARK_GRAY}Enter domain name ->> {RESET}")
    subdomains = []
    try:
        # Get the IP address of the domain
        ip_address = socket.gethostbyname(domain)

        # Loop through a range of common subdomains and attempt to resolve each one
        for i in range(1, 10):
            subdomain = f"test{i}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
            except socket.error:
                pass

        # Search for subdomains using search engines
        search_urls = [
            f"https://www.google.com/search?q=site:{domain}",
            f"https://search.yahoo.com/search?p=site:{domain}",
            f"https://www.bing.com/search?q=site:{domain}",
        ]
        for url in search_urls:
            try:
                res = requests.get(url)
                soup = BeautifulSoup(res.text, 'html.parser')
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href.startswith('http') and domain in href:
                        subdomain = href.split('//')[1].split('.')[0]
                        if subdomain not in subdomains:
                            subdomains.append(subdomain)
            except requests.exceptions.RequestException:
                pass

        # Query ChatGPT for additional subdomains
        #chatgpt_key = openai_secret_manager.get_secret("openai")["api_key"]
        #headers = {"Authorization": f"Bearer {chatgpt_key}"}
        #prompt = f"List additional subdomains for {domain}"
        #response = requests.post("https://api.openai.com/v1/engines/davinci-codex/completions", json={"prompt": prompt, "max_tokens": 1024, "n": 1, "stop": "==="}, headers=headers)
        #if response.ok:
        #    completions = response.json()["choices"][0]["text"].strip().split("\n")
        #    for completion in completions:
        #        subdomain = completion.strip()
        #        if subdomain not in subdomains:
        #            subdomains.append(subdomain)

       # Check HTTP response status for each subdomain
        print(f"Subdomains for {domain}:")
        for subdomain in subdomains:
            url = f"https://{subdomain}.{domain}"
            try:
                res = requests.get(url)
                print(f"{subdomain}: {res.status_code} {res.reason}")
            except requests.exceptions.RequestException:
                print(f"{subdomain}: Could not connect to {url}")

    except socket.gaierror:
        print(f"Could not resolve hostname {domain}")

    except KeyboardInterrupt:
        # If the user presses CTRL-C, exit the program
        print("Exiting program")
        exit()


def sub_path():

    # Define the target domain to crawl
    target_domain = input (f'''{DARK_GRAY}host - >> {RESET}''')

    # Send a request to the target domain and parse the HTML response
    response = requests.get(f"http://{target_domain}")
    html = response.text

    # Extract all href links from the HTML response
    links = html.split('href="')[1:]
    hrefs = [link.split('"')[0] for link in links]

    # Extract sub-paths from hrefs that include the target domain
    sub_paths = []
    for href in hrefs:
        if target_domain in href:
            sub_path = urlparse(href).path
            if sub_path != "":
                sub_paths.append(sub_path)

    # Remove duplicates and sort the sub-paths alphabetically
    sub_paths = sorted(list(set(sub_paths)))

    # Print the list of sub-paths found
    for sub_path in sub_paths:
        print(sub_path)


def server_side():

        # define target url
        target_url = input(f"{DARK_GRAY}Enter domain name ->> {RESET}")

        # run nikto scan and output results to a file
        output_file = "nikto_results.txt"
        subprocess.run(["nikto", "-h", target_url, "-output", output_file])


def vulnerability():

    # Set up target URL and ZAP API key
    target_url = input(f"{DARK_GRAY}Enter domain name ->> {RESET}")

    api_key = "4o2ug9s6eq0beevuq0n9if40dm"

    # Create ZAP instance and start scanning
    zap = ZAPv2(apikey=api_key)
    zap.urlopen(target_url)
    zap.spider.scan(target_url)
    zap.ascan.scan(target_url)

    # Retrieve list of vulnerabilities
    alerts = zap.core.alerts()

    # Print out results
    print(f"Total alerts found: {len(alerts)}")
    for alert in alerts:
        print(f"Alert: {alert['alert']} at URL: {alert['url']}")


def main_menu():
    desc()
    
    # Print the banner with red color
    print(f""" {GREEN}
        ▓▓         ▓ 33333  ▒▒▒▒▒    ▓▓▓▓▓▓  ████  II PPPPP  33333  RR   RR
        ▓▓   ▓▓   ▓      33 ▒▒   ▒▒ ███     ▓▓  ▓▓ II PP   P     33 RR RR  R
        ▓▓  ▓ ▓  ▓  33333   ▒▒▒▒▒    ▓▓▓▓   ██  ██ II PPPPP 33333   RRR
        ▓▓ ▓   ▓         33 ▒▒   ▒▒     ███ ██  ██ II PP         33 RR
        ▓▓    ▓▓  3333333   ▒▒▒▒▒   ▓▓▓▓▓▓  ██  ██ II PP  3333333   RR {RESET} Version 1.0
    {YELLOW}
        ||O|||H |||T |||S ||| |||P ||| |||R |||O |||J |||E |||C |||T || {RESET}
    {BLUE}
                w3bsnip3r written by: Haseef Ahmed
                github:{RESET} https://github.com/mn-haseef/w3bsnip3r.git 
                
                {RED}Web Application Security Framework {RESET}

    """)
    print(f'''{GREEN}Options{RESET}

    [1] Information Gathering 
    [2] Find Sub Domain
    [3] Find Sub Path 
    [4] Vulnerability Scan "Nikto"
    [5] Vulnerability Scan "Zap-Proxy"
    [6] Exit
    ''')

    try:
        i = input(f'''{BLUE}Select Option ->> {RESET}''')
    except:
        print('Invalid')
        sys.exit()

    if i == '-help':
        info()
        sys.exit()
    elif int(i) == 1:
        server_info()
    elif int(i) == 2:
        find_subdomains()
    elif int(i) == 3:
        sub_path()
    elif int(i) == 4:
        server_side()
    elif int(i) == 5:
        vulnerability()
    elif int(i) == 6:
      print(f'''{RED}Terminated !!{RESET}''')
      sys.exit()

    else:
        print(f'''{RED}Entered an Incorrect Value{RESET}''')
        sys.exit()

    main_menu()

main_menu()
