
# re or Regular Expression,  a built-in library in python used for working with Regular Expressions
import re
import email

''' Parses a string containing an RFC 2822 email address and returns a tuple (realname, email_address).
  parseaddr("John Doe <john@example.com>")
  # → ('John Doe', 'john@example.com') 
  --> Used during From, To email extraction
  '''
'''
parsedate_to_datetime --> Parses an RFC 2822 date string (the format used in email headers like Date:) and returns a datetime object.
parsedate_to_datetime("Mon, 20 Nov 2023 14:30:00 +0530")
# → datetime.datetime(2023, 11, 20, 14, 30, tzinfo=...)
'''
from email.utils import parseaddr, parsedate_to_datetime


# Function 1 : This function use above parseaddr function to return  (realname, email_address, domain)
def parse_email_address(raw_address):
    """
       Takes a raw address string like 'PayPal Security <scammer@evil.com>'
       and returns a dictionary with display_name, email, and domain.
    """
    if not raw_address:
        # Sometime the path like Reply-To or any other part can be empty "" or None, so instead of returning error it returns ..
        # Here None and "" are True and actual email is False.
        return {"display_name": "", "email": "", "domain": ""}

    display_name, email_addr = parseaddr(raw_address) # It does : sender "PayPal Security <scammer@evil.com>" to "PayPal Security""scammer@evil.com"

    # Extract domain from the email address
    if "@" in email_addr:
        # Splits "scammer@evil.com" on @ and takes the right side:
        '''
        "scammer@evil.com".split("@")    # → ["scammer", "evil.com"]
                                  [1]    # → "evil.com"
        '''
        domain = email_addr.split("@")[1]  # the username and domain are in list, so [1] points to domain
    else:
        domain = ""

    return {
        "display_name":display_name,
        "email": email_addr,
        "domain": domain
    }


# Function 2: Extract all url's from email body [html,text]

def extract_urls(body_text, body_html):
    """
        Finds every URL in the email body.
        Searches plain text for bare URLs and HTML for href attributes.
        Returns a deduplicated list.
    """
    urls = []  # list that store all url's in a email body

    # Pattern for plain text urls
    url_pattern = r"https?://[^\s<>\"']+"  # here r means treat this as a raw string

    # Pattern for URLs inside href="..." attributes
    href_pattern = r"href=[\"'](https?://[^\"']+)[\"']"  # [\"'] ==> closing quote and opening quote

    if body_text:
        # scans entire body_text
        # returns every URL it finds as a list
        urls.extend(re.findall(url_pattern,body_text))

    if body_html:
        urls.extend(re.findall(href_pattern,body_html))
        urls.extend(re.findall(url_pattern, body_html))

        # Remove duplicates while converting to a list
    return list(set(urls))  # A set only keeps unique values, duplicates are automatically removed


# Function 3: Parse email date into a datetime object
def parse_date(date_string):
        """
            Converts an RFC 2822 date string like 'Mon, 26 May 2026 10:30:00 +0545'
            into a Python datetime object. Returns None if parsing fails.
        """

        if not date_string:
            # if header is missing, return None safely instead of crashing.
            return None

        try:
            #"Mon, 26 May 2026 10:30:00 +0545"
           # ↓
           # datetime(2026, 5, 26, 10, 30, 0, tzinfo=+05:45)
            return parsedate_to_datetime(date_string)
        except Exception:
            return None

# Function 4: Detect display name vs domain mismatch
def detect_display_name_mismatch(sender_string):
   """
     If we do research on phishing mail, most of the phishing are generated using the name of popular brands.
     What this function does is to check if the domain of the email address matches the domain of the email address.
     If the domain of the email address does not match the domain of the email address, it is likely that the email address is commonly impersonated brands.
     Only a simple layer to of protection in email analysis.
   """
   if not sender_string:
       return False

       # Map of brand names to their legitimate domain(s)
   BRAND_DOMAINS = {
       "paypal": ["paypal.com", "paypal.co.uk", "email.paypal.com"],
       "apple": ["apple.com", "icloud.com"],
       "microsoft": ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
       "google": ["google.com", "gmail.com", "googlemail.com"],
       "amazon": ["amazon.com", "amazon.co.uk", "amazon.in"],
       "netflix": ["netflix.com"],
       "facebook": ["facebook.com", "meta.com", "facebookmail.com"],
       "instagram": ["instagram.com"],
       "twitter": ["twitter.com", "x.com"],
       "linkedin": ["linkedin.com", "e.linkedin.com"],
       "dropbox": ["dropbox.com"],
       "stripe": ["stripe.com"],
       "github": ["github.com", "githubusercontent.com"],
   }

    # Calling the function we discussed earlier —> breaks "PayPal Security <scammer@evil.com>" into structured parts
   parsed = parse_email_address(sender_string)
   display_name = parsed["display_name"].lower()
   domain = parsed["domain"].lower()

   for brand, legit_domains in BRAND_DOMAINS.items():
       if brand in display_name:
           # Brand name found in display name — check if domain is legitimate
           if domain not in legit_domains:
               return True  # MISMATCH: display says "PayPal" but domain is not paypal.com

   return False


# Function 5: Main parser ; orchestrates all functions above

def parse_email(email_record):
    """
    Central parsing pipeline for PhishGuard.

    Takes a raw EmailRecord from the database and extracts all
    structured data needed by the analyzer services:
        - Sender identity (display name, email, domain)
        - All headers as a clean dictionary
        - Plain text and HTML body
        - All URLs from both body types
        - Attachments and pixel tracker signals
        - Parsed datetime object from the Date header

    Returns a single dictionary consumed by:
        header_analyzer.py  → sender, authentication headers
        keyword_detector.py → body_text
        ioc_extractor.py    → urls
        ml_classifier.py    → full parsed output

    Does not modify the EmailRecord — read only.
    """

    # Re-parse the raw bytes into a full message object
      # email_record.raw_email contains the full raw email stored in the database.
    # bytes() ensures the data is in byte format.
    raw_bytes = bytes(email_record.raw_email)
    message = email.message_from_bytes(raw_bytes)

    # Parse structured fields
    sender = parse_email_address(email_record.sender)  # This accesses the sender field from the EmailRecord Django model object.
    recipient = parse_email_address(email_record.recipient)
    reply_to = parse_email_address(email_record.reply_to)
    parsed_date = parse_date(email_record.date)
    urls = extract_urls(email_record.body_text, email_record.body_html)
    mismatch = detect_display_name_mismatch(email_record.sender)

    return {
        "id": email_record.id,
        "uid": email_record.uid,
        "message_id": email_record.message_id,
        "sender": sender,
        "recipient": recipient,
        "reply_to": reply_to,
        "cc": email_record.cc,
        "bcc": email_record.bcc,
        "subject": email_record.subject,
        "parsed_date": parsed_date,
        # Authentication headers (header_analyzer needs these)
        "return_path": email_record.return_path,
        "x_mailer": email_record.x_mailer,
        "received_spf": email_record.received_spf,
        "dkim_signature": email_record.dkim_signature,
        "dmarc": email_record.dmarc,
        "received_chain": email_record.received_chain,
        # Analysis-ready fields
        "urls": urls,
        "url_count": len(urls),
        "display_name_mismatch": mismatch,
        "has_attachments": email_record.has_attachments,
        "is_multipart": email_record.is_multipart,
        "source_folder": email_record.source_folder,
        "body_text": email_record.body_text,
        "body_html": email_record.body_html,
    }
