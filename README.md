<div align="center">

# 🛡️ PhishGuard

### AI-Powered Email Phishing Detection & Analysis System

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Django](https://img.shields.io/badge/Django-6.0-092E20?style=for-the-badge&logo=django&logoColor=white)](https://djangoproject.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-Academic-blue?style=for-the-badge)]()

**PhishGuard** is a comprehensive email phishing detection system that combines **IMAP-based email ingestion**, **multi-layered threat analysis**, **machine learning classification**, and **real-time threat intelligence** to protect organizations from phishing attacks.

---

</div>

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Analysis Pipeline](#analysis-pipeline)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [User Roles](#user-roles)
- [API Integrations](#api-integrations)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

PhishGuard is designed for organizations that need automated, intelligent email security monitoring. It connects to any IMAP-compatible mailbox, fetches incoming emails in real-time, and runs them through an **8-stage analysis pipeline** that produces a final risk score (0–100) and a security verdict (**Safe**, **Suspicious**, or **Malicious**).

When a malicious email is detected, PhishGuard automatically sends alert notifications to the affected recipients and logs all Indicators of Compromise (IOCs) for future threat intelligence.

---

## Key Features

### 🔍 Multi-Layered Email Analysis
- **Email Parsing** — Extracts headers, body text, HTML content, and attachments from raw IMAP emails
- **Header Authentication Analysis** — Validates SPF, DKIM, and DMARC records; detects Reply-To mismatches and suspicious sender patterns
- **IOC Extraction** — Identifies and catalogs URLs, IP addresses, domains, email addresses, and file hashes from email content
- **Keyword Detection** — Scans subject lines and body text against curated phishing keyword dictionaries using NLP techniques
- **Threat Intelligence Lookup** — Cross-references extracted IOCs with VirusTotal, AbuseIPDB, Google Safe Browsing, and MalwareBazaar
- **ML Classification** — Classifies emails using a trained Multinomial Naive Bayes model (scikit-learn) with TF-IDF vectorization
- **Risk Scoring Engine** — Combines all analysis scores using a weighted dual-formula system to produce a final 0–100 risk score
- **Automated Alerting** — Sends real-time email alerts when malicious emails are detected

### 👥 Role-Based Access Control
- **Admin** — Full system control: user management, API key configuration, system settings
- **Analyst** — Email analysis, IOC investigation, mailbox configuration, dashboard access
- **Employee** — View analyzed email reports, IOC overviews, account management

### 📊 Interactive Dashboard
- Real-time statistics on analyzed emails
- Verdict distribution charts
- IOC investigation interface
- Email detail drill-down views

### 💳 eSewa Payment Integration
- Payment gateway integration for premium features
- Supports the eSewa digital wallet (Nepal)

---

## System Architecture

![Uploading image.png…]()


---

## Analysis Pipeline

PhishGuard processes each email through an **8-step sequential pipeline**:

| Step | Service | Input | Output | Score Range |
|------|---------|-------|--------|-------------|
| **3.1** | `email_parser.py` | Raw IMAP email | Parsed headers, subject, body text, attachments | — |
| **3.2** | `header_analyzer.py` | Parsed headers | Authentication score (SPF/DKIM/DMARC validation) | 0–30 |
| **3.3** | `ioc_extractor.py` | Body text & HTML | Extracted URLs, IPs, domains, hashes → saved to DB | — |
| **3.4** | `keyword_detector.py` | Subject + body | Keyword match score across phishing categories | 0–15 |
| **3.5** | `threat_intel.py` | Extracted IOCs | IOC risk score from external threat APIs | 0 or 35 |
| **3.6** | `ml_classifier.py` | Body text | ML phishing probability score | 0–100 |
| **3.7** | `risk_scorer.py` | All four scores | Final weighted risk score + verdict + classification | 0–100 |
| **3.8** | `analyze_email.py` | Risk result | Saved to AnalysisReport + alert email if malicious | — |

### Verdict Classification

| Risk Score | Verdict | Classification |
|-----------|---------|----------------|
| 0–39 | ✅ **Safe** | Clean |
| 40–69 | ⚠️ **Suspicious** | Spam |
| 70–100 | 🚨 **Malicious** | Phishing |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend Framework** | Django 6.0 (Python 3.10+) |
| **Database** | PostgreSQL 15+ |
| **Machine Learning** | scikit-learn (MultinomialNB + TF-IDF) |
| **NLP** | NLTK |
| **Email Protocol** | IMAP (imaplib) |
| **Threat Intelligence** | VirusTotal, AbuseIPDB, Google Safe Browsing, MalwareBazaar |
| **Frontend** | Django Templates, HTML5, CSS3, JavaScript |
| **UI Libraries** | Bootstrap (via CDN), Lucide Icons, Montserrat Font |
| **Payment Gateway** | eSewa (Nepal) |
| **Environment Config** | python-dotenv |

---

## Project Structure

```
PhishGuard/
├── PhishGuard/                 # Django project configuration
│   ├── settings.py             # Database, apps, middleware config
│   ├── urls.py                 # Central URL routing (70+ endpoints)
│   ├── wsgi.py                 # WSGI entry point
│   └── asgi.py                 # ASGI entry point
│
├── Mailbox/                    # Email ingestion & mailbox management
│   ├── models.py               # EmailRecord, EmailAttachment, MailBox
│   └── services/
│       ├── imap_fetcher.py     # IMAP connection & email fetching
│       ├── email_sender.py     # SMTP alert & notification sender
│       ├── setup_imap.py       # Mailbox CRUD & connection testing
│       └── user_data.py        # IOC loading, API key management
│
├── analyzer/                   # Core analysis engine
│   ├── models.py               # IOC, AnalysisReport, ApiKeys
│   └── services/
│       ├── email_parser.py     # MIME parsing & content extraction
│       ├── header_analyzer.py  # SPF/DKIM/DMARC authentication checks
│       ├── ioc_extractor.py    # URL, IP, domain, hash extraction
│       ├── keyword_detector.py # Phishing keyword NLP matching
│       ├── threat_intel.py     # VirusTotal, AbuseIPDB, SafeBrowsing API
│       ├── ml_classifier.py    # MultinomialNB email classification
│       ├── risk_scorer.py      # Weighted risk scoring engine
│       ├── analyze_email.py    # Main pipeline orchestrator
│       ├── analyzed_data_apis.py # Dashboard & report APIs
│       └── ml_models/
│           ├── model.pkl       # Trained Naive Bayes model
│           └── vectorizer.pkl  # TF-IDF vectorizer
│
├── accounts/                   # User authentication & management
│   ├── models.py               # User, EsewaPayment
│   └── services.py             # Login, register, RBAC, credential management
│
├── frontend/                   # UI layer
│   ├── views.py                # Template rendering & eSewa payment
│   ├── templates/
│   │   ├── login.html          # Split-screen login interface
│   │   ├── dashboard.html      # Analytics dashboard
│   │   ├── admin/              # Admin panel templates
│   │   ├── analyst/            # Analyst panel templates
│   │   └── employee/           # Employee panel templates
│   └── static/
│       ├── Logo.png            # PhishGuard falcon logo
│       ├── dashboard.js        # Dashboard chart logic
│       ├── emailData.js        # Email analysis UI logic
│       └── library/            # Third-party JS/CSS libraries
│
├── reports/                    # Reports app (reserved)
├── dashboard/                  # Dashboard app (reserved)
├── manage.py                   # Django management script
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (API keys, DB creds)
└── .gitignore                  # Git ignore rules
```

---

## Prerequisites

Before setting up PhishGuard, ensure you have:

- **Python** 3.10 or higher
- **PostgreSQL** 15 or higher
- **pip** (Python package manager)
- **Git**
- A **Gmail account** (or any IMAP-compatible email) with App Password enabled
- API keys for threat intelligence services (optional but recommended):
  - [VirusTotal API Key](https://www.virustotal.com/gui/join-us)
  - [AbuseIPDB API Key](https://www.abuseipdb.com/account/api)
  - [Google Safe Browsing API Key](https://console.cloud.google.com/)
  - [MalwareBazaar API Key](https://bazaar.abuse.ch/)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/PhishGuard.git
cd PhishGuard
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Download NLTK Data

```bash
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords'); nltk.download('punkt_tab')"
```

### 5. Set Up PostgreSQL

```sql
-- Connect to PostgreSQL and create the database
CREATE DATABASE phishguard_db;

-- Verify
\l
```

### 6. Apply Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### 7. Run the Development Server

```bash
python manage.py runserver
```

The application will be available at **http://127.0.0.1:8000/**

---

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# Django
SECRET_KEY=your_django_secret_key

# IMAP Configuration (Monitored Mailbox)
IMAP_HOST=imap.gmail.com
IMAP_EMAIL=your-monitor@gmail.com
IMAP_PASSWORD=your_app_password

# Alert Email Sender
IMAP_SENDER_EMAIL=your-sender@gmail.com
IMAP_SENDER_PASSWORD=your_sender_app_password
RECIPIENT_EMAIL=your-monitor@gmail.com

# Threat Intelligence API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
MALWAREBAZAAR_API_KEY=your_malwarebazaar_api_key

# PostgreSQL Database
DB_NAME=phishguard_db
DB_USER=postgres
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432
```

### Gmail App Password Setup

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable **2-Step Verification**
3. Navigate to **App passwords**
4. Generate a new app password for "Mail"
5. Use this 16-character password in your `.env` file

---

## Usage

### First-Time Setup

1. **Start the server** and navigate to `http://127.0.0.1:8000/`
2. **Create an Admin account** — The first user registration automatically gets the Admin role
3. **Log in as Admin** and create Analyst and Employee accounts
4. **Configure the mailbox** — Navigate to IMAP Setup and add your monitored mailbox credentials
5. **Add API keys** — Configure threat intelligence API keys through the admin interface

### Running an Analysis

1. Log in as an **Analyst**
2. Click **Analyze Emails** — This triggers the full 8-step pipeline:
   - Fetches new emails from the configured IMAP mailbox
   - Parses, extracts IOCs, runs keyword detection
   - Queries threat intelligence APIs
   - Classifies with ML model
   - Calculates final risk score
   - Saves reports and sends alerts for malicious emails
3. View results in the **Dashboard** and **Email Data** pages

### Investigating IOCs

1. Navigate to the **IOC Investigation** page
2. Browse all extracted Indicators of Compromise
3. View threat scores, malicious flags, and source details
4. Cross-reference with threat intelligence databases

---

## User Roles

| Role | Capabilities |
|------|-------------|
| **Admin** | Create/delete users, manage system settings, view user list, configure API keys |
| **Analyst** | Run email analysis, configure mailboxes, investigate IOCs, view dashboard, manage reports |
| **Employee** | View analyzed email reports, check IOC overviews, manage own account |

---

## API Integrations

PhishGuard integrates with the following external threat intelligence services:

| Service | Purpose | Free Tier |
|---------|---------|-----------|
| **VirusTotal** | URL, domain, IP, and file hash reputation scanning | 4 requests/min |
| **AbuseIPDB** | IP address abuse confidence scoring | 1,000 checks/day |
| **Google Safe Browsing** | URL threat matching against Google's threat lists | 10,000 calls/day |
| **MalwareBazaar** | File hash lookup against known malware samples | Unlimited |

---

## Database Schema

### Core Models

| Model | App | Description |
|-------|-----|-------------|
| `EmailRecord` | Mailbox | Stores fetched emails (headers, body, raw data, authentication fields) |
| `EmailAttachment` | Mailbox | Stores extracted attachments with file hashes |
| `MailBox` | Mailbox | Configured IMAP mailbox credentials |
| `IOC` | Analyzer | Indicators of Compromise (URLs, IPs, domains, hashes) with threat scores |
| `AnalysisReport` | Analyzer | Final analysis results (risk score, verdict, classification, sub-scores) |
| `ApiKeys` | Analyzer | Stored API keys for threat intelligence services |
| `User` | Accounts | User accounts with role-based access (admin, analyst, employee) |
| `EsewaPayment` | Accounts | Payment status tracking for premium features |

---

## ML Model Details

- **Algorithm:** Multinomial Naive Bayes
- **Feature Extraction:** TF-IDF Vectorization
- **Training Data:** Zero-Day Phishing Emails Corpus (~31 MB) + SMS Spam Collection
- **Output:** Phishing probability score (0–100)
- **Model Files:**
  - `analyzer/services/ml_models/model.pkl` — Trained classifier
  - `analyzer/services/ml_models/vectorizer.pkl` — TF-IDF vectorizer

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m "Add your feature"`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## License

This project is developed as part of an academic 6th Semester project.

---

## Acknowledgements

- [scikit-learn](https://scikit-learn.org/) — Machine learning library
- [NLTK](https://www.nltk.org/) — Natural language processing
- [Django](https://www.djangoproject.com/) — Web framework
- [VirusTotal](https://www.virustotal.com/) — Threat intelligence API
- [AbuseIPDB](https://www.abuseipdb.com/) — IP abuse database
- [Google Safe Browsing](https://safebrowsing.google.com/) — URL threat detection

---

<div align="center">

**Built with ❤️ for safer email communication**

</div>

