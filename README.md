# 🛡️ Threat Intelligence Extraction Tool
*Automated Cybersecurity Report Analysis with MITRE ATT&CK Mapping and VirusTotal Integration*

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://opensource.org/licenses/MIT)
[![Open Source](https://badges.frapsoft.com/os/v2/open-source.svg?v=103)](https://github.com/prajjwaltiwarii/THREAT-INTELLIGENCE-EXTRACTION-TOOL)

<img src="https://github.com/prajjwaltiwarii/THREAT-INTELLIGENCE-EXTRACTION-TOOL/assets/placeholder-image.jpg" width="800" alt="Tool Demo">

## 📖 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Format](#-output-format)
- [Repo Structure](#-repository-structure)
- [Support](#-support)
- [License](#-license)

## 🎯 Features
- **PDF Analysis**: Extract text from multi-page threat reports
- **IoC Detection**: 
  - IP Addresses (`192.168.1.1`) 
  - Domains (`evil.com`)
  - File Hashes (MD5/SHA1/SHA256)
  - Email Addresses
- **Threat Intelligence**:
  - MITRE ATT&CK TTP Mapping
  - Threat Actor Identification
  - Targeted Industry Detection
- **Malware Analysis** (with VirusTotal API):
  - Hash Reputation Lookup
  - Detection Statistics
  - File Metadata

## 💻 Installation

### Prerequisites
- Python 3.8+
- VirusTotal API Key (Optional)

### Quick Start
```bash
# Clone repository
git clone https://github.com/prajjwaltiwarii/THREAT-INTELLIGENCE-EXTRACTION-TOOL.git
cd THREAT-INTELLIGENCE-EXTRACTION-TOOL

# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_sm 

 
## 🖥️ Usage

### Basic Command
```bash
python script.py.py -i <input.pdf>

Full Analysis with VirusTotal
python script.py.py -i <input.pdf> -k <API_KEY>

Custom Output Fields
python script.py -i <input.pdf> -f <field1> <field2>...
## 🔧 Custom Output Options

### Available Fields
| CLI Option          | Description                          | JSON Key               |
|---------------------|--------------------------------------|------------------------|
| `iocs`              | Indicators of Compromise             | `IoCs`                 |
| `ttps`              | MITRE ATT&CK Tactics & Techniques    | `TTPs`                 |
| `threat_actors`     | Threat Actor Groups/Individuals      | `Threat Actor(s)`      |
| `malware`           | Malware Details & Hashes             | `Malware`              |
| `targeted_entities` | Targeted Industries/Organizations    | `Targeted Entities`    |

**Default Behavior**: All fields included if none specified

### Example Combinations
```bash
# Get only IoCs and Malware data
python script.py -i report.pdf -f iocs malware

# Focus on attack patterns
python script.py -i report.pdf -f ttps targeted_entities

# Minimal output (just actors and targets)
python script.py -i report.pdf -f threat_actors targeted_entities

Output:
usage: threat_intel_extractor.py [-h] -i INPUT [-k K] [-f [F ...]]

Extract threat intelligence from PDF reports

options:
  -i                    INPUT, Input PDF file path (required)
  -k                    VirusTotal API key (optional)
  -f                    Output fields: iocs|ttps|threat_actors|malware|targeted_entities

📄 Sample Output

{
  "IoCs": {
    "IP_addresses": ["192.168.1.105"],
    "Domains": ["evil-domain.net"],
    "Hashes": ["a1b2c3d4e5f6..."],
    "Emails": ["phish@evil-domain.net"]
  },
  "TTPs": {
    "Tactics": [{"TA0001": "Initial Access"}],
    "Techniques": [{"T1566.001": "Spearphishing Attachment"}]
  },
  "Threat_Actor(s)": ["APT29"],
  "Malware": [
    {
      "Name": "Shamoon",
      "md5": "a1b2c3d4...",
      "sha256": "d4e5f6...",
      "tags": ["wiper", "destructive"]
    }
  ],
  "Targeted_Entities": ["Energy Sector"]
}

📂 Repository Structure

THREAT-INTELLIGENCE-EXTRACTION-TOOL/
├── script.py  # Main script
├── requirements.txt           # Dependency list
├── sample_report.pdf          # Example input
├── output.json                # Sample output
└── README.md                  # This document
