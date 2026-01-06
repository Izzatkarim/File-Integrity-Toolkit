import requests
import hashlib
import logging
import os
from configparser import ConfigParser

def get_virustotal_api_key():
    config = ConfigParser()
    config.read('config.ini')
    return config.get('VIRUSTOTAL', 'api_key', fallback=None)

def calculate_sha256(file_path):
    """Calculate file hash for VirusTotal lookup"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def check_virustotal(file_path, api_key):
    """
    Pure API-based detection
    Returns: 
        None if error
        {'positives': X, 'total': Y, 'scan_date': ...} if successful
    """
    if not api_key:
        logging.warning("No API key provided")
        return None

    try:
        # Step 1: Upload file if small (<32MB)
        file_size = os.path.getsize(file_path)
        if file_size < 32 * 1024 * 1024:  # VirusTotal's upload limit
            with open(file_path, 'rb') as f:
                response = requests.post(
                    'https://www.virustotal.com/api/v3/files',
                    headers={'x-apikey': api_key},
                    files={'file': f},
                    timeout=30
                )
            if response.status_code == 200:
                return response.json().get('data', {}).get('attributes', {})
        
        # Step 2: Fallback to hash lookup
        file_hash = calculate_sha256(file_path)
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{file_hash}',
            headers={'x-apikey': api_key},
            timeout=15
        )
        return response.json().get('data', {}).get('attributes', {})
        
    except Exception as e:
        logging.error(f"VirusTotal API error: {str(e)}")
        return None
