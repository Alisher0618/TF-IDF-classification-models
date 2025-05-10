"""
Python script to check if domain name is alive for future analysis
"""
__author__ = "Alisher Mazhirinov"

import requests, os
import pandas as pd
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

def fetch_html(domain):
    # Attempts to fetch the HTML content of the given domain.
    # Returns the domain if successful, or None if there is a request error.
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        response.raise_for_status()  # HTTP Error Checking
        return domain
    except requests.RequestException:
        return None


# Arguments handler
parser = argparse.ArgumentParser(description="Get HTML page\nProgram to check if domain name is available. If available, save the domain name. If not, skip. Example: python3 findAliveDomainName.py -p path/to/file")
parser.add_argument("-p", "--phishing", action="store_true", help="Flag to check phishing file")
parser.add_argument("-m", "--malware", action="store_true", help="Flag to check malware file")
parser.add_argument("-c", "--cesnet", action="store_true", help="Flag to check benign cesnet file")
parser.add_argument("-u", "--umbrella", action="store_true", help="Flag to check benign umbrella file")
parser.add_argument("filename", type=str, help="Path ot the file name.")

args = parser.parse_args()
print(f"File: {args.filename}")

if args.phishing:
    phish_directory = "1_raw_domains/phishing/csvs/"
    filepath = os.path.join(phish_directory, args.filename)
    if os.path.exists(filepath):
        print("Phishing file is selected.")
        print("File exists.", filepath)
        check = args.filename.replace(".csv", "") + "_alive.csv"
        if os.path.exists("2_alive_domains/phishing/" + check):
            x = input("You have already checked this file. Do you want to continue? (y/n): ")
            if x.lower() != "y":
                print("Exiting...")
                exit(0)
    else:
        print("File does not exist")
        exit(1)
elif args.malware:
    malw_directory = "1_raw_domains/malware/csvs/"
    filepath = os.path.join(malw_directory, args.filename)
    if os.path.exists(filepath):
        print("Malware file is selected.")
        print("File exists.", filepath)
        check = args.filename.replace(".csv", "") + "_alive.csv"
        if os.path.exists("2_alive_domains/malware/" + check):
            x = input("You have already checked this file. Do you want to continue? (y/n): ")
            if x.lower() != "y":
                print("Exiting...")
                exit(0)
    else:
        print("File does not exist")
        exit(1)
elif args.cesnet:
    cesn_directory = "1_raw_domains/benign_cesnet/csvs/"
    filepath = os.path.join(cesn_directory, args.filename)
    if os.path.exists(filepath):
        print("Benign cesnet file is selected.")
        print("File exists.", filepath)
        check = args.filename.replace(".csv", "") + "_alive.csv"
        if os.path.exists("2_alive_domains/benign_cesnet/" + check):
            x = input("You have already checked this file. Do you want to continue? (y/n): ")
            if x.lower() != "y":
                print("Exiting...")
                exit(0)
    else:
        print("File does not exist")
        exit(1)
elif args.umbrella:
    umbr_directory = "1_raw_domains/benign_umbrella/csvs/"
    filepath = os.path.join(umbr_directory, args.filename)
    if os.path.exists(filepath):
        print("Benign umbrella file is selected.")
        print("File exists.", filepath)
        check = args.filename.replace(".csv", "") + "_alive.csv"
        if os.path.exists("2_alive_domains/benign_umbrella/" + check):
            x = input("You have already checked this file. Do you want to continue? (y/n): ")
            if x.lower() != "y":
                print("Exiting...")
                exit(0)
    else:
        print("File does not exist")
        exit(1)

x = input("Do you want to continue? (y/n): ")
if x.lower() == "n":
    print("Exiting...")
    exit(0)
else:
    print("Continuing...")
    available_domains = []
    amount = 0
    passed = 0
    save_threshold = 100
    lock = threading.Lock()
    
    df = pd.read_csv(filepath)
    domains = df["domain_name"].tolist()
    new_filename = args.filename.replace(".csv", "") + "_alive.csv"


    # Concurrently checks a list of domains using ThreadPoolExecutor.
    # For each successfully reachable domain, prints status and saves results periodically to a CSV file.
    # The save path depends on the given category argument (phishing, malware, etc.).
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {executor.submit(fetch_html, domain): domain for domain in domains}

        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                with lock:
                    passed += 1
                    if result is not None:
                        print(f"{result} is available. Total found: {amount}, checked: {passed}")
                        available_domains.append(result)
                        amount += 1
                    
                    # Periodic saving
                    if len(available_domains) % save_threshold == 0:
                        df = pd.DataFrame(available_domains, columns=["domain_name"])
                        print(f"{len(available_domains)} is saved in file.")
                        if args.phishing:
                            df.to_csv("2_alive_domains/phishing/" + new_filename, index=False, encoding='utf-8')
                            print(f"Scrapping completed. Available domains saved to {new_filename}")
                        elif args.malware:
                            df.to_csv("2_alive_domains/malware/" + new_filename, index=False, encoding='utf-8')
                            print(f"Scrapping completed. Available domains saved to {new_filename}")
                        elif args.cesnet:
                            df.to_csv("2_alive_domains/benign_cesnet/" + new_filename, index=False, encoding='utf-8')
                            print(f"Scrapping completed. Available domains saved to {new_filename}")
                        elif args.umbrella:
                            df.to_csv("2_alive_domains/benign_umbrella/" + new_filename, index=False, encoding='utf-8')
                            print(f"Scrapping completed. Available domains saved to {new_filename}")
                        else:
                            df.to_csv("2_alive_domains/bruh/" + new_filename, index=False, encoding='utf-8')
                            print(f"Scrapping completed. Available domains saved to {new_filename}")
            except Exception as e:
                print(f"Error with {domain}: {e}")
            
    df = pd.DataFrame(available_domains, columns=["domain_name"])
    if args.phishing:
        df.to_csv("2_alive_domains/phishing/" + new_filename, index=False, encoding='utf-8')
        print(f"Scrapping completed. Available domains saved to {new_filename}")
    elif args.malware:
        df.to_csv("2_alive_domains/malware/" + new_filename, index=False, encoding='utf-8')
        print(f"Scrapping completed. Available domains saved to {new_filename}")
    elif args.cesnet:
        df.to_csv("2_alive_domains/benign_cesnet/" + new_filename, index=False, encoding='utf-8')
        print(f"Scrapping completed. Available domains saved to {new_filename}")
    elif args.umbrella:
        df.to_csv("2_alive_domains/benign_umbrella/" + new_filename, index=False, encoding='utf-8')
        print(f"Scrapping completed. Available domains saved to {new_filename}")
    else:
        df.to_csv("2_alive_domains/bruh/" + new_filename, index=False, encoding='utf-8')
        print(f"Scrapping completed. Available domains saved to {new_filename}")
