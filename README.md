THREAT INTELLIGENCE EXTRACTION TOOL
===================================

Extract cybersecurity insights from PDF reports with one command

WHAT DOES THIS TOOL DO?
-----------------------
This Python script helps you automatically pull critical security information from PDF threat reports. It finds:

- Suspicious IPs, domains, and email addresses
- Hacker tactics mapped to MITRE ATT&CK framework
- Malware details (with VirusTotal integration)
- Targeted companies/industries
- Known threat actor groups

Perfect for security analysts working with PDF reports!

REQUIREMENTS
------------
- Python 3.8+ (tested on 3.10)
- 4GB+ RAM (for processing large reports)
- Linux/Mac/Windows (works on all major OS)

QUICK SETUP
-----------
1. Get the code:
   git clone https://github.com/prajjwaltiwarii/THREAT-INTELLIGENCE-EXTRACTION-TOOL.git
   cd THREAT-INTELLIGENCE-EXTRACTION-TOOL

2. Install requirements:
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm

3. (Optional) Get a VirusTotal API key:
   https://www.virustotal.com/

HOW TO USE IT
-------------
Basic extraction (generates JSON automatically):
python threat_intel_extractor.py -i report.pdf

With malware analysis (needs API key):
python threat_intel_extractor.py -i report.pdf -k YOUR_VT_KEY

Customize output fields:
python threat_intel_extractor.py -i report.pdf -f iocs malware

SAMPLE OUTPUT
-------------
{
  "IoCs": {
    "IP addresses": ["192.168.1.1"],
    "Domains": ["example.com"],
    "Hashes": ["a1b2c3..."],
    "Emails": ["phish@example.com"]
  },
  "TTPs": {
    "Tactics": [{"TA0001": "Initial Access"}],
    "Techniques": [{"T1566.001": "Spear-phishing Attachment"}]
  },
  "Threat Actor(s)": ["APT33"],
  "Malware": [
    {
      "Name": "Shamoon",
      "md5": "a1b2c3...",
      "sha256": "d4e5f6...",
      "tags": ["wiper"]
    }
  ],
  "Targeted Entities": ["Energy Sector"]
}

REPOSITORY STRUCTURE
--------------------
/PS-1
├── threat_intel_extractor.py  # Main script
├── requirements.txt           # Dependencies
├── sample_report.pdf          # Example input
├── output.json                # Sample output
└── README.md                  # This file

LICENSE: MIT
CONTACT: Open an issue on GitHub https://github.com/prajjwaltiwarii/PS-1/issues
