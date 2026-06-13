import re
from analyzer.models import IOC
from Mailbox.models import EmailRecord
from urllib.parse import urlparse

def extract_ips(text):
    """
        Find all valid IPv4 addresses in an email given text string. We passed email text string as argument to this function
        Checks that all four octets are between 0 and 255.
    """
    if not text:
        return []

    # Matches standard 4 - octet address in a given text string
    # Check that all four octet are between 0 and 255
    # Use regex to find all patterns matching: digits.digits.digits.digits
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    possible_ips = re.findall(ip_pattern,text)

    valid_ips = []  # After checking, if the ip is valid from the text they are stored like this: ["192.168.1.1", "8.8.8.8"]

    for ip in possible_ips:
        try:
            # Split the IP into parts
            parts = ip.split(".")

            # converts each part of an IP address eg. ['192', '168', '1', '10'] from a string to an integer
            octets = []
            for part in parts:
                octets.append(int(part))

            # Check that each octet is between 0 and 255; if all are valid, add the IP to the valid_ips list.
            is_valid = True
            for octet in octets:
                if octet < 0 or octet > 255:
                    is_valid = False
                    break

            # If valid, add to the list
            if is_valid:
                valid_ips.append(ip)

        except ValueError:
            # Skip if conversion to integer fails
            continue

    return valid_ips


def extract_domains_from_urls(urls):
    """
    Extract the domain name (netloc) from a list of URLs.
    Strips port numbers (e.g. 'evil.com:8080' -> 'evil.com') and deduplicates.
    """

    # If urls is empty ([]) or None, return an empty list immediately.
    if not urls:
        return []

    # A set automatically removes duplicate values.domains = {"google.com", "google.com", "example.com"} => {"google.com", "example.com"}
    domains = set()

    # The loop processes one URL at a time.
    for url in urls:
        # If a URL is None or an empty string (""), skip it and move to the next one.
        if not url:
            continue
        try:
            """
            urlparse() is a function from Python's urllib.parse module that breaks a URL into its 
            different components, such as the scheme, domain, path, query, etc.
            """
            parsed = urlparse(url)

            # extracts the network location (domain name and optional port number) from the parsed URL.
            # url = "https://google.com/search" to google.com
            netloc = parsed.netloc # python function
            if netloc:
                # Remove port number if present: netloc = "example.com:8080" => domain = "example.com"
                domain = netloc.split(':')[0]
                domains.add(domain)
        except Exception:
            # If urlparse() or another operation fails, skip that URL and continue processing the rest.
            continue

    return list(domains)
