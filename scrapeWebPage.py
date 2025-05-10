"""
Python script for scraping webpages
"""
__author__ = "Alisher Mazhirinov"

import requests
import aiohttp
import asyncio
from bs4 import BeautifulSoup
import pandas as pd
import langid
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os
import argparse

# Arguments handler
parser = argparse.ArgumentParser(description="Get HTML page\nProgram to check if domain name is available. If available, scrappe the HTML page. If not, skip")
parser.add_argument("-p", "--phishing", action="store_true", help="Scrappe phishing file")
parser.add_argument("-m", "--malware", action="store_true", help="Scrappe malware file")
parser.add_argument("-c", "--cesnet", action="store_true", help="Scrappe benign cesnet file")
parser.add_argument("-u", "--umbrella", action="store_true", help="Scrappe benign umbrella file")
parser.add_argument("filename", type=str, help="Path ot the file name. Example: python3 scrapeWebPage.py -p alive_phishing.csv")

args = parser.parse_args()
print(f"File: {args.filename}")
INPUT_FILE = ""
OUTPUT_FILE = ""
LABEL_VALUE = 0

if args.phishing:
    phish_directory = "2_alive_domains/phishing/"
    filepath = os.path.join(phish_directory, args.filename)
    if os.path.exists(filepath):
        print("Phishing file is selected.")
        print("File exists.", filepath)
        check = args.filename.replace("alive.csv", "") + "scrapped.csv"
        OUTPUT_FILE = "3_scrapped_domains/phishing/" + check
        INPUT_FILE = "2_alive_domains/phishing/" + args.filename
        LABEL_VALUE = 1
        if os.path.exists(OUTPUT_FILE):
            x = input("You have already checked this file. Do you want to continue? (y/n): ")
            if x.lower() != "y":
                print("Exiting...")
                exit(0)
    else:
        print("File does not exist")
        exit(1)
elif args.malware:
    malw_directory = "2_alive_domains/malware/"
    filepath = os.path.join(malw_directory, args.filename)
    if os.path.exists(filepath):
        print("Malware file is selected.")
        print("File exists.", filepath)
        check = args.filename.replace("alive.csv", "") + "scrapped.csv"
        OUTPUT_FILE = "3_scrapped_domains/malware/" + check
        INPUT_FILE = "2_alive_domains/malware/" + args.filename
        LABEL_VALUE = 1
        if os.path.exists(OUTPUT_FILE):
            x = input("You have already checked this file. Do you want to continue? (y/n): ")
            if x.lower() != "y":
                print("Exiting...")
                exit(0)
    else:
        print("File does not exist")
        exit(1)
elif args.cesnet:
    cesn_directory = "2_alive_domains/benign_cesnet/"
    filepath = os.path.join(cesn_directory, args.filename)
    if os.path.exists(filepath):
        print("Benign cesnet file is selected.")
        print("File exists.", filepath)
        check = args.filename.replace("alive.csv", "") + "scrapped.csv"
        OUTPUT_FILE = "3_scrapped_domains/benign_cesnet/" + check
        INPUT_FILE = "2_alive_domains/benign_cesnet/" + args.filename
        if os.path.exists(OUTPUT_FILE):
            x = input("You have already checked this file. Do you want to continue? (y/n): ")
            if x.lower() != "y":
                print("Exiting...")
                exit(0)
    else:
        print("File does not exist")
        exit(1)
elif args.umbrella:
    umbr_directory = "2_alive_domains/benign_umbrella/"
    filepath = os.path.join(umbr_directory, args.filename)
    if os.path.exists(filepath):
        print("Benign umbrella file is selected.")
        print("File exists.", filepath)
        check = args.filename.replace("alive.csv", "") + "scrapped.csv"
        OUTPUT_FILE = "3_scrapped_domains/benign_umbrella/" + check
        INPUT_FILE = "2_alive_domains/benign_umbrella/" + args.filename
       
        if os.path.exists(OUTPUT_FILE):
            x = input("You have already checked this file. Do you want to continue? (y/n): ")
            if x.lower() != "y":
                print("Exiting...")
                exit(0)
    else:
        print("File does not exist")
        exit(1)


print(f"\nInput file: {INPUT_FILE}")
print(f"Output file: {OUTPUT_FILE}")
print(f"Label value: {LABEL_VALUE}")


x = input("Do you want to continue? (y/n): ")
if x.lower() == "n":
    print("Exiting...")
    exit(0)
else:
    df = pd.read_csv(INPUT_FILE)
    print("Continuing...")

    # Load already processed domains if the file exists
    if os.path.exists(OUTPUT_FILE):
        processed_df = pd.read_csv(OUTPUT_FILE)
        processed_domains = set(processed_df["domain_name"])
        print(f"Loaded {len(processed_domains)} domains already processed.")
    else:
        processed_domains = set()

    df = df[~df["domain_name"].isin(processed_domains)]

    # Variables
    not_scrapped = [] # Failed domains
    all_data = [] # Data about domains
    session = requests.Session() # Session for requests
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    lock = threading.Lock() # Lock for thread-safe update
    checked = 0 # Counter of processed domains
    success = 0 # Counter of successful requests
    SAVE_INTERVAL = 100 # Save progress every 100 domains


    # Malicious tag analysis function
    def check_malicious_tags(soup):
        malicious_tags_count = {
            "iframe": len(soup.find_all("iframe")),
            "script": len(soup.find_all("script", src=True)),
            "meta_refresh": len(soup.find_all("meta", attrs={"http-equiv": "refresh"})),
            "hidden_input": len(soup.find_all("input", type="hidden")),
            "object": len(soup.find_all("object")),
            "embed": len(soup.find_all("embed")),
            "applet": len(soup.find_all("applet")),
            "form": len(soup.find_all("form", action=True)),
            "link_js": len(soup.find_all("link", attrs={"rel": "stylesheet", "href": True})),
            "on_event": len(soup.find_all(lambda tag: any(attr.startswith("on") for attr in tag.attrs)))
        }

        # Count all tags on a page
        all_tags = [tag.name for tag in soup.find_all()]
        all_tags_count = dict(Counter(all_tags))

        return malicious_tags_count, all_tags_count


    # Text clearing function
    def clean_text(soup):
        for script in soup(["script", "style"]):
            script.decompose()
        text = soup.get_text(separator=" ")
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:50000]


    # Synchronous page load function (quick check)
    def fetch_html(domain):
        try:
            response = session.get(f"http://{domain}", timeout=5)
            response.raise_for_status()
            return response.text
        except requests.RequestException:
            return None

    # Progress saving function
    def save_progress():
        df_progress = pd.DataFrame(all_data)
        df_progress.to_csv(OUTPUT_FILE, index=False, encoding='utf-8', escapechar="\\")
        print(f"Progress saved! {len(all_data)} domains recorded.")

    # Asynchronous page load function (if synchronous one failed)
    async def fetch_and_extract(session, url, domain_name):
        global checked, success
        headers = {"User-Agent": "Mozilla/5.0"}

        try:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}")

                html = await response.text(errors="ignore")
                soup = BeautifulSoup(html, 'html.parser')
                page_text = clean_text(soup)
                malicious_tags, all_tags = check_malicious_tags(soup)

                if page_text:
                    lang, confidence = langid.classify(page_text)
                    with lock:
                        all_data.append({
                            'domain_name': domain_name,
                            'label': LABEL_VALUE,
                            'language': lang,
                            'malicious_tags': sum(malicious_tags.values()),
                            'all_tags': sum(all_tags.values()),
                            'text': page_text
                        })
                        success += 1

                        # Periodic saving of progress
                        if success % SAVE_INTERVAL == 0:
                            save_progress()

                else:
                    with lock:
                        not_scrapped.append(domain_name)

        except Exception:
            with lock:
                not_scrapped.append(domain_name)

        with lock:
            checked += 1
            print(f"Processed: {checked} | Success: {success} | Failed: {len(not_scrapped)}")


    # Main download function
    async def main():
        global checked, success

        # Primary check with requests in multithreaded mode
        print("Starting multithreaded download...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {executor.submit(fetch_html, row["domain_name"]): row["domain_name"] for _, row in df.iterrows()}

            tasks = []
            async with aiohttp.ClientSession() as session:
                for future in as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        with lock:
                            checked += 1
                        if result:
                            soup = BeautifulSoup(result, 'html.parser')
                            page_text = clean_text(soup)
                            malicious_tags, all_tags = check_malicious_tags(soup)

                            if page_text:
                                lang, confidence = langid.classify(page_text)
                                with lock:
                                    all_data.append({
                                        'domain_name': domain,
                                        'label': LABEL_VALUE,
                                        'language': lang,
                                        'malicious_tags': sum(malicious_tags.values()),
                                        'all_tags': sum(all_tags.values()),
                                        'text': page_text
                                    })
                                    success += 1

                                    # Periodic saving of progress
                                    if success % SAVE_INTERVAL == 0:
                                        save_progress()

                            else:
                                with lock:
                                    not_scrapped.append(domain)
                        else:
                            print(f"Failed to load: {domain}")
                            tasks.append(fetch_and_extract(session, f"http://{domain}", domain))

                    except Exception:
                        with lock:
                            not_scrapped.append(domain)

        # Asynchronous processing of remaining domains
        if tasks:
            print("Starting asynchronous loading...")
            await asyncio.gather(*tasks)

        # Final save
        save_progress()


    # Launch the parser
    asyncio.run(main())
