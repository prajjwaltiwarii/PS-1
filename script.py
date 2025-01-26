import re
import json
import spacy
import pdfplumber
import argparse
from vt import Client
from typing import Dict, List, Optional
from pathlib import Path

# Initialize spaCy NLP model
nlp = spacy.load("en_core_web_sm")

# Field configuration
ALLOWED_FIELDS = {
    'iocs': 'IoCs',
    'ttps': 'TTPs',
    'threat_actors': 'Threat Actor(s)',
    'malware': 'Malware',
    'targeted_entities': 'Targeted Entities'
}

# MITRE ATT&CK Mappings
MITRE_TACTICS = {
    'initial access': 'TA0001',
    'execution': 'TA0002',
    'persistence': 'TA0003',
    'privilege escalation': 'TA0004',
    'defense evasion': 'TA0005',
    'credential access': 'TA0006',
    'discovery': 'TA0007',
    'lateral movement': 'TA0008',
    'collection': 'TA0009',
    'command and control': 'TA0011',
    'exfiltration': 'TA0010',
    'impact': 'TA0040'
}

MITRE_TECHNIQUES = {
    'spear-phishing attachment': 'T1566.001',
    'powershell': 'T1059.001',
    'scheduled task': 'T1053.005',
    'windows management instrumentation': 'T1047',
    'file and directory discovery': 'T1083',
    'lateral tool transfer': 'T1570'
}

def extract_text_from_pdf(pdf_path: str) -> str:
    """Extract text content from PDF file"""
    text = ""
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text += page.extract_text() + "\n"
    return text

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract Indicators of Compromise using regex patterns"""
    patterns = {
        'IP addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'Domains': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        'Hashes': r'\b[a-fA-F0-9]{32,256}\b',
        'Emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    }
    
    return {
        category: list(set(re.findall(pattern, text)))
        for category, pattern in patterns.items()
    }

def extract_entities(text: str) -> Dict[str, List[str]]:
    """Extract Threat Actors and Targeted Entities using spaCy NER"""
    doc = nlp(text)
    entities = {
        'Threat Actors': [],
        'Targeted Entities': []
    }
    
    for ent in doc.ents:
        if ent.label_ in ['ORG', 'PERSON']:
            entities['Threat Actors'].append(ent.text)
        elif ent.label_ in ['ORG', 'GPE', 'NORP']:
            entities['Targeted Entities'].append(ent.text)
    
    # Deduplicate and clean
    entities['Threat Actors'] = list(set(entities['Threat Actors']))
    entities['Targeted Entities'] = list(set(entities['Targeted Entities']))
    
    return entities

def extract_ttps(text: str) -> Dict[str, List[Dict]]:
    """Extract MITRE ATT&CK TTPs using keyword matching"""
    tactics = []
    techniques = []
    
    # Match tactics
    for tactic_name, tactic_id in MITRE_TACTICS.items():
        if re.search(r'\b' + re.escape(tactic_name) + r'\b', text, re.IGNORECASE):
            tactics.append({tactic_id: tactic_name.title()})
    
    # Match techniques
    for tech_name, tech_id in MITRE_TECHNIQUES.items():
        if re.search(r'\b' + re.escape(tech_name) + r'\b', text, re.IGNORECASE):
            techniques.append({tech_id: tech_name.title()})
    
    return {'Tactics': tactics, 'Techniques': techniques}

def enrich_malware_data(hashes: List[str], vt_api_key: Optional[str]) -> List[Dict]:
    """Enrich malware information using VirusTotal API"""
    if not vt_api_key or not hashes:
        return []
    
    malware_data = []
    with Client(vt_api_key) as client:
        for file_hash in hashes:
            try:
                file_obj = client.get_object(f"/files/{file_hash}")
                
                # Convert all values to JSON-serializable types
                malware_entry = {
                    'Name': str(getattr(file_obj, 'meaningful_name', 'Unknown')),
                    'md5': str(file_obj.md5),
                    'sha1': str(file_obj.sha1),
                    'sha256': str(file_obj.sha256),
                    'ssdeep': str(getattr(file_obj, 'ssdeep', 'N/A')),
                    'TLSH': str(getattr(file_obj, 'tlsh', 'N/A')),
                    'tags': list(getattr(file_obj, 'tags', [])),
                    'last_analysis_stats': dict(file_obj.last_analysis_stats)
                }
                
                malware_data.append(malware_entry)
                
            except Exception as e:
                print(f"Error processing hash {file_hash}: {str(e)}")
                continue
    
    return malware_data

def process_threat_report(pdf_path: str, vt_api_key: Optional[str] = None) -> Dict:
    """Main processing function"""
    text = extract_text_from_pdf(pdf_path)
    iocs = extract_iocs(text)
    entities = extract_entities(text)
    ttps = extract_ttps(text)
    
    # Enrich malware data
    malware_data = enrich_malware_data(iocs['Hashes'], vt_api_key)
    
    # Combine results
    full_report = {
        'IoCs': {k: v for k, v in iocs.items() if v},
        'TTPs': ttps,
        'Threat Actor(s)': entities['Threat Actors'],
        'Malware': malware_data,
        'Targeted Entities': entities['Targeted Entities']
    }
    
    return full_report

def filter_output(data: Dict, fields: List[str]) -> Dict:
    """Filter output data based on selected fields"""
    filtered = {}
    field_map = {k.lower(): v for k, v in ALLOWED_FIELDS.items()}
    
    for field in fields:
        clean_field = field.lower().strip()
        if clean_field in field_map:
            key = ALLOWED_FIELDS[clean_field]
            filtered[key] = data.get(key, [])
        else:
            print(f"Warning: Invalid field '{field}' will be ignored")
    
    return filtered or data  # Return all fields if none specified

def save_to_json(data: Dict, output_path: str) -> None:
    """Save results to JSON file"""
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    parser = argparse.ArgumentParser(
        description='Extract threat intelligence from PDF reports',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-i', '--input', required=True, 
                       help='Input PDF file path')
    parser.add_argument('-k', help='VirusTotal API key (optional)')
    parser.add_argument('-f', '--fields', nargs='+',
                      help=f'''Select fields to include in output (available options):
{chr(10).join([f"- {v} (use: {k})" for k, v in ALLOWED_FIELDS.items()])}
Default: Include all fields''')
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file {input_path} not found!")
        return
    
    # Process report
    report_data = process_threat_report(
        pdf_path=str(input_path),
        vt_api_key=args.k
    )
    
    # Filter output if fields specified
    if args.fields:
        report_data = filter_output(report_data, args.fields)
    
    # Generate output path
    output_path = input_path.with_suffix('.json')
    save_to_json(report_data, str(output_path))
    print(f"Successfully generated report at {output_path}")

if __name__ == "__main__":
    main()
