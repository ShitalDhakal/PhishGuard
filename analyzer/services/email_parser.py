"""
Email Parser Service
====================
Parses raw email bytes into structured data (headers + body).

Input:  Raw email bytes (from EmailRecord.raw_email)
Output: Dictionary containing headers and body text

Usage:
    from analyzer.services.email_parser import parse_email
    result = parse_email(raw_email_bytes)
"""

import email
from email import policy
from email.parser import BytesParser


def parse_email(raw_email_bytes):
    """
    Parse raw email bytes into a structured dictionary.

    Args:
        raw_email_bytes (bytes): Raw email content fetched via IMAP

    Returns:
        dict: Parsed email with headers and body
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)

    parsed = {
        "headers": extract_headers(msg),
        "body_text": extract_body(msg, content_type="text/plain"),
        "body_html": extract_body(msg, content_type="text/html"),
        "attachments": extract_attachments(msg),
    }

    return parsed


def extract_headers(msg):
    """
    Extract all important headers from the email.

    Args:
        msg: EmailMessage object

    Returns:
        dict: Key headers needed for analysis
    """
    return {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
        "received": msg.get_all("Received", []),
        "x_mailer": msg.get("X-Mailer", ""),
        "x_priority": msg.get("X-Priority", ""),
    }


def extract_body(msg, content_type="text/plain"):
    """
    Extract the email body (plain text or HTML).

    Args:
        msg: EmailMessage object
        content_type: "text/plain" or "text/html"

    Returns:
        str: The email body text
    """
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == content_type:
                disposition = str(part.get("Content-Disposition", ""))
                if "attachment" not in disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body += payload.decode(charset, errors="ignore")
    else:
        if msg.get_content_type() == content_type:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                body = payload.decode(charset, errors="ignore")

    return body


def extract_attachments(msg):
    """
    Extract attachment metadata (filename, type, size, raw bytes for hashing).

    Args:
        msg: EmailMessage object

    Returns:
        list: List of attachment info dicts
    """
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                payload = part.get_payload(decode=True)
                attachments.append({
                    "filename": part.get_filename() or "unknown",
                    "content_type": part.get_content_type(),
                    "size": len(payload) if payload else 0,
                    "raw_bytes": payload,
                })

    return attachments
