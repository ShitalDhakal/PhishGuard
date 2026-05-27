
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

