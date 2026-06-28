from multiprocessing.sharedctypes import Value
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


def extract_email_addresses(text):
    """
    Find all email addresses embedded in the body text using a precise regex pattern.
    Requires a top-level domain of at least 2 characters.
    """
    if not text:
        # If text is None or an empty string (""), the function returns an empty list.
        return []


    # This pattern matches email addresses
    pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'

    # re.findall() searches the text and returns all matching email addresses as a list.
    # like this ['support@example.com', 'admin@test.org']
    return re.findall(pattern, text)

def extract_iocs(parsed_data):
    """
    Master orchestrator. Receives parsed email dictionary, extracts URLs,
    domains, IPs (body + received headers), and email addresses.
    Deduplicates and returns list of unique IOC dictionaries.
    """
    iocs = []
    """
    Example after extraction:
    iocs = [
    {"type": "url", "value": "https://evil.com", "source": "body"},
    {"type": "ip", "value": "192.168.1.1", "source": "header"}
    ]
    """
    # 1. Extract URLs (already parsed/deduplicated in email_parser.py from function 2
    # ........Remove duplicates while converting to a list
    #         return list(set(urls)) )
    urls = parsed_data.get("urls", [])
    # If "urls" doesn't exist, it returns an empty list [].
    for url in urls:
        # Loop Through Each URL

        # Creates a dictionary describing the IOC and adds it to iocs.
        iocs.append({
            "type": "url",
            "value": url,
            "source": "body"
        })

   # 2. Extract Domains (derived from parsed URLs)
    domains = extract_domains_from_urls(urls)
    """ Example
    urls = [
    "https://evil.com/login",
    "https://google.com/search"
    ]
    returns:
     domains = [
    "evil.com",
    "google.com"
    ]
    """
    for domain in domains:
        # Store Each Domain as an IOC
        iocs.append({
            "type": "domain",
            "value": domain,
            "source": "url"
        })

    # 3. Extract IP Addresses

    body_text = parsed_data.get("body_text")
    # Gets the email's plain text body.
    if body_text:
        body_ips = extract_ips(body_text)
        for ip in body_ips:
            iocs.append({
                "type": "ip",
                "value": ip,
                "source": "body"
            })
            """
            {
                "type": "ip",
                "value": "192.168.1.10",
                "source": "body"
            }
            """
    # From received headers chain
    # Gets the list of Received: email headers.
    received_chain = parsed_data.get("received_chain")
    if received_chain:
        for header_string in received_chain:
            if header_string:
                # Extract IPs from Header
                header_ips = extract_ips(header_string)
                for ip in header_ips:
                    iocs.append({
                        "type": "ip",
                        "value": ip,
                        "source": "header"
                    })
                """ {
                    "type": "ip",
                    "value": "203.0.113.5",
                    "source": "header"
                    }
                """
    # 4. Extract Email Addresses (excluding the sender's own address)
    # Combine text and HTML bodies so we don't miss anything in HTML-only emails
    text_to_search = ""
    # Get the plain text and HTML bodies
    body_text = parsed_data.get("body_text") # If body_text exists, append it to text_to_search.
    body_html = parsed_data.get("body_html")

    if body_text:
        text_to_search += body_text + " "
    if body_html:
        text_to_search += body_html
    # Only continue if at least one of body_text or body_html contains data.
    if text_to_search:
        emails = extract_email_addresses(text_to_search)
        sender = parsed_data.get("sender")
        sender_email = ""
        if isinstance(sender, dict):
            sender_email = sender.get("email") or ""
        elif isinstance(sender, str):
            sender_email = sender
        # This removes extra spaces and ignores uppercase/lowercase differences.
        sender_email_lower = sender_email.strip().lower()
        # Skip the sender's own email, only store email different from sender
        for email_addr in emails:
            if email_addr.strip().lower() != sender_email_lower:
                iocs.append({
                    "type": "email",
                    "value": email_addr,
                    "source": "body"
                })

    # 5. Extract File Hashes from email attachments
    email_id = parsed_data.get("id") # Gets the email's database ID from parsed_data.
    if email_id:
        try:
            email_record = EmailRecord.objects.get(id=email_id)
            # Loop through all attachments, if contains
            for attachment in email_record.attachments.all(): # Gets every attachment linked to that email.
                if attachment.file_hash:
                    iocs.append({
                        "type": "hash",
                        "value": attachment.file_hash,
                        "source": "attachment"
                    })
        except EmailRecord.DoesNotExist:
            pass



    seen = set()
    """
        This block removes duplicate IOCs (Indicators of Compromise) so that each unique IOC appears only once.
    """
    unique_iocs = []

    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    return unique_iocs


def save_iocs(email_record, ioc_list):
    """
    Saves a list of extracted unique IOCs to the database associated with the email_record.
    Returns the count of new database entries successfully created.
    """
    for ioc in ioc_list:
                # Django part: get_or_create() is a Django ORM method that Gets an existing database record if it already exists.
                # Creates a new record if it does not exist.

        file_hash = ""
        email_id_s = email_record.get("id")

        ioc_value = None

        if(ioc["type"] == "file"):
            file_hash = ioc["file_hash"]
            ioc_value = IOC.objects.filter(file_hash=ioc["file_hash"]).first()
        else:
            ioc_value = IOC.objects.filter(value=ioc["value"]).first()

        if ioc_value:
            email_id_array = [int(num) for num in ioc_value.email_ids.split(",")]
            for num in email_id_array:
                if num == int(email_id_s):
                    return
            ioc_value.email_ids += f", {email_id_s}"
            ioc_value.save()
        else:
            obj, created = IOC.objects.get_or_create(

                email_ids=email_id_s,
                ioc_type=ioc["type"],
                value=ioc["value"],
                source=ioc["source"],
                is_malicious=None,
                threat_score=None

            )