import imaplib
import email
import hashlib
from Mailbox.models import EmailRecord, EmailAttachment, MailBox as mailbox
from django.http import JsonResponse
from datetime import datetime, timedelta, timezone

from analyzer.models import IOC


def fetch_emails(request):
    """
    This function connects to an IMAP server, fetches all unseen emails,
    parse them and saves each headers body on the database.
    """

    # I am assuming only one mail exists 
    data = list(mailbox.objects.all().values())

    username = data[0]["address"]
    password = data[0]["app_password"]
    imap_host = data[0]["imap_server"]  # We can dynamically change the IMAP host (Outlook, Gmail, Zoho) from the env file.
    # If IMAP_HOST is missing from .env → uses "imap.gmail.com" silently. No error.

    if not username or not password:
        print("Error: Missing IMAP credentials in .env files .")
        return JsonResponse({"message":"Invalid credentials, please setup IMAP properly.", "status": 403})


    # ===== This first establish connection to google imap server and process login ========
    imap = imaplib.IMAP4_SSL(imap_host)  #creates an SSL-encrypted TCP connection to Gmail's IMAP server on port 993.
    imap.login(username,password)    # Server will respond with a status tagged result, like 'OK' if the login was successful, or 'NO' if it failed.
    # imap.select("INBOX", readonly=True)

    # Checking which folder to scan, for now it scan INBOX and SPAM folders
    folders = ["INBOX","[Gmail]/Spam"]

    for folder in folders:
        print(f"\n{'=' * 60}")
        print(f"Scanning: {folder}")
        print(f"{'=' * 60}")

        status, _ = imap.select(f'"{folder}"', readonly=True)  # readonly=True : Open the mailbox in read-only model,
        # If we parse email, the parsed email isn't marked as seen
        if status != "OK":
            print(f"Could not select folder: {folder}")
            continue

        # Next, Step 3: search for UNSEEN emails

        latest_email = EmailRecord.objects.order_by('fetched_at').last()
        latest_date = "01-Jan-1970"
        if latest_email:
            latest_date = latest_email.fetched_at.strftime("%d-%b-%Y")

        status, msg_ids = imap.search(None, f"SINCE {latest_date}") 
        if status != "OK" or not msg_ids[0]:
            print(f"No emails found in {folder}.")
            continue

        # msg_ids looks like: msg_ids = [b'3 7 12 19']   # one bytes object inside a list
        email_ids = msg_ids[0].split()  # msg_ids[0].split()  # → [b'3', b'7', b'12', b'19']   split on spaces
        print(f"Found {len(email_ids)} emails(s) in {folder}.")

        # Next, step 4: loop through each email
        for email_id in email_ids:
            # Fetch raw byte from each email
            _, msg_data = imap.fetch(email_id, "(RFC822)")
            '''
            What RFC822 means?
            --> RFC822 is an email format standard. Requesting "(RFC822)" tells the server to send the 
            complete message exactly as stored — headers and body together, unparsed. It's the most complete fetch option.
            '''
            raw_bytes = msg_data[0][1] # Return complete raw email

            # Parse into a structured Python object
            message =  email.message_from_bytes(raw_bytes)

            # This is checked after the below loop finished: STEP 8: UID Deduplication
            # Use Message-ID as the unique identifier
            message_id = message.get("Message-ID", "")
            uid_value = f"{folder}:{email_id.decode()}"
            if EmailRecord.objects.filter(uid=uid_value).exists():
                print(f"  Skipping {uid_value} — already in database.")
                continue

            # Extract Headers
            sender = message.get("From")
            recipient = message.get("To")
            cc = message.get("Cc")
            bcc = message.get("Bcc")
            subject = message.get("Subject")
            date = message.get("Date")
            reply_to = message.get("Reply-To")
            return_path = message.get("Return-Path")
            x_mailer = message.get("X-Mailer")


            # Authentication Headers
            received_spf = message.get("Received-SPF")
            dkim_signature = message.get("Dkim-Signature")

            # DMARC live inside authentication headers
            auth_results = message.get("Authentication-Results","")
            dmarc = auth_results if "dmarc" in auth_results.lower() else None

            received_chain = message.get_all("Received")

            # Body extraction part
            body_text = None
            body_html = None
            attachment_list = []  # Collects attachments here temporarily

            if message.is_multipart():
                for part in message.walk():
                    content_type = part.get_content_type()
                    disposition = part.get_content_disposition()

                    # STEP 6: Detect Attachments
                    if disposition == "attachment" or part.get_filename():
                        payload = part.get_payload(decode =True)   # Python’s email module used to extract the actual content/data of an email part.
                        if payload:
                            attachment_list.append({
                                "filename": part.get_filename(),
                                "content_type": content_type,
                                "size": len(payload),
                                "file_hash": hashlib.sha256(payload).hexdigest(),
                                "content": payload,
                            })
                        continue

                    # Extract text bodies
                    if content_type == "text/plain" and body_text is None:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode(errors="replace")
                    elif content_type == "text/html" and body_html is None:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html = payload.decode(errors="replace")

            else:
                # For Single-part email,just grab the payload directly
                payload = message.get_payload(decode=True)
                if payload:
                    if message.get_content_type() == "text/html":
                        body_html = payload.decode(errors="replace")
                    else:
                        body_text = payload.decode(errors="replace")

            # Moving to step 9: Save parshed email content's into the database
            record = EmailRecord.objects.create(
                uid=uid_value,
                message_id=message_id,
                source_folder=folder,
                # Headers
                sender=sender,
                recipient=recipient,
                cc=cc,
                bcc=bcc,
                subject=subject,
                date=date,
                reply_to=reply_to,
                return_path=return_path,
                x_mailer=x_mailer,
                # Authentication
                received_spf=received_spf,
                dkim_signature=dkim_signature,
                dmarc=dmarc,
                received_chain=received_chain,
                # Body
                body_text=body_text,
                body_html=body_html,
                # Raw data
                raw_email=raw_bytes,
                # Metadata flags
                is_multipart=message.is_multipart(),
                has_attachments=len(attachment_list) > 0,
                score = 0,
                scanned = False
            )

            #  Save Attachments
            for att in attachment_list:
                ioc_list = IOC.objects.filter(file_hash=att["file_hash"])
                if ioc_list.exists():
                    ioc = ioc_list.first()
                    # If the IOC already exists, append this email's ID to its email_ids field
                    if str(record.id) not in ioc.email_ids.split(","):
                        ioc.email_ids += f",{record.id}"
                        ioc.save()

                else:
                    IOC.objects.create(
                        email_ids=str(record.id),
                        ioc_type="hash",
                        value=att["filename"],
                        file_hash=att["file_hash"],
                        source="attachment",
                        detected_at=datetime.now(timezone.utc),
                        is_malicious=None,
                        threat_score=None,
                    )

            print(f" Saved: [{uid_value}] {subject}")
            if attachment_list:
                print(f"📎 {len(attachment_list)} attachment(s)")

        # Now get relief, we just completed the worst part, now log out
    imap.logout()
    print(f"\n{'=' * 60}")
    print("Fetch complete.")
    print(f"{'=' * 60}")
    return JsonResponse({"message":"Fetched successfully", "status": 200})


def read_mail_from_db(request):
    role = request.session.get("login_user_role")
    if(role != "analyst"):
        return JsonResponse({"message":"Only analyst can perform this action", "status": 403})
    else:
        data = list(EmailRecord.objects.all().values("uid", "sender", "recipient", "subject", "date", "body_text"))
        print(data)
        return JsonResponse({"status":200,"data":data}, safe=False)


# Add this at the very bottom of imap_fetcher.py:
if __name__ == "__main__":
    fetch_emails(None)













