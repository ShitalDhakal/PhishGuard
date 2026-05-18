import imaplib
import email
from collections import defaultdict
import os

from dotenv import load_dotenv


def fetch_email():
    load_dotenv()
    username = os.getenv("IMAP_EMAIL")
    password = os.getenv("IMAP_PASSWORD")

    if not username or not password:
        print("Error: Missing IMAP credentials in .env files .")
        return  []  # return [] returns an empty list ; a list with zero elements.
    imap = imaplib.IMAP4_SSL("imap.gmail.com")  #creates an SSL-encrypted TCP connection to Gmail's IMAP server on port 993.
    imap.login(username,password)    # Server will respond with a status tagged result, like 'OK' if the login was successful, or 'NO' if it failed.
    imap.select("INBOX", readonly=True)


    # FIND MOST RECENT UNSEEN
    # status is 'OK' on success, else 'NO' or 'BAD'.
    # msg_ids is a list like [b'1 2 5 10'] if messages found, or [b''] if none.
    status, msg_ids = imap.search(None, "UNSEEN")
    if status != "OK" or not msg_ids[0]:
        print("No unread messages.")
        imap.logout()
        exit()

    latest_id = max(msg_ids[0].split(), key=int)

    # imap.fetch(latest_id, "(RFC822)") => Download the full raw email from the server.
    # "(RFC822)"data item — fetch the entire raw email (headers + body)
    # _status "OK" or "NO" — ignored here with _
    _, msg_data = imap.fetch(latest_id, "(RFC822)")
    '''
    What RFC822 means?
    --> RFC822 is an email format standard. Requesting "(RFC822)" tells the server to send the 
    complete message exactly as stored — headers and body together, unparsed. It's the most complete fetch option.
    '''
    message = email.message_from_bytes(msg_data[0][1])   #  parses the raw email bytes into a structured Python object.

    #  PRINT ALL HEADERS
    print("=" * 60)
    print("ALL HEADERS (most recent unread)")
    print("=" * 60)
    for key, value in message.items():
        print(f"{key}: {value}")

    # PRINT BODY
    print("=" * 60)
    print("BODY")
    print("=" * 60)

    '''
    The core question: is the email one piece or many?
    Simple email          →  just one body (like a plain letter)
    Multipart email       →  multiple parts (text + HTML + attachments)
    Your sample email was multipart/mixed — meaning it had multiple parts bundled together.
    '''

    # Checks if the email has multiple parts. Your sample email had Content-Type: multipart/mixed so this returns True.
    # If it was a simple plain text email, it returns False.
    if message.is_multipart():
        for part in message.walk():
            '''
            walk() iterates through every part of the email one by one, like opening folders inside folders:
            multipart/mixed        ← iteration 1
            ├── text/plain     ← iteration 2
            ├── text/html      ← iteration 3
            └── application/pdf← iteration 4
            '''
            if part.get_content_type() == "text/plain":
                print("[TEXT]")
               #At each iteration, checks what type the current part is. Skips text/html, application/pdf etc.
               #Only proceeds when it finds text/plain.
                print(part.get_payload(decode=True).decode())
               # get_payload(decode=True)extracts the content, decodes base64/quoted-printable → gives bytes
               # .decode()converts bytes → readable string

            elif part.get_content_type() == "text/html":
                print("[HTML]")
                print(part.get_payload(decode=True).decode())

            elif part.get_content_type() == "application/pdf":
                print("Pdf attachment detected!")



    else:
        print(message.get_payload(decode=True).decode())
        #This runs when is_multipart() is False — meaning the email has a single body only.
        #No need to walk, just grab the payload directly.

    imap.logout()





fetch_email()

