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

 
