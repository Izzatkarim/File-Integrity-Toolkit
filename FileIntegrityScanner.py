import os
import hashlib
import json
import logging
import requests
import time
from datetime import datetime, timezone
from configparser import ConfigParser
from report_generator import create_pdf_report

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('file_integrity.log'),
        logging.StreamHandler()
    ]
)
logging.getLogger("fontTools").setLevel(logging.WARNING)

class FileIntegrityScanner:
    def __init__(self):
        self.file_hashes = {}
        self.findings = []
        self.scan_time = None
        self.max_file_size = 650 * 1024 * 1024  # VirusTotal's file size limit
    
    def calculate_hash(self, file_path, algorithm='sha256'):
        """Calculate file hash with error handling"""
        try:
            hash_func = getattr(hashlib, algorithm)()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            logging.error(f"Hash error for {file_path}: {str(e)}")
            return None
    
    def scan_directory(self, path):
        """Scan directory and collect file hashes"""
        if not os.path.exists(path):
            logging.error(f"Path not found: {path}")
            return False
        
        self.scan_time = datetime.now(timezone.utc).isoformat()
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if os.path.getsize(file_path) > self.max_file_size:
                        logging.warning(f"Skipping large file: {file_path}")
                        continue
                        
                    stats = os.stat(file_path)
                    self.file_hashes[file_path] = {
                        'path': file_path,
                        'size': stats.st_size,
                        'hashes': {
                            'md5': self.calculate_hash(file_path, 'md5'),
                            'sha1': self.calculate_hash(file_path, 'sha1'),
                            'sha256': self.calculate_hash(file_path, 'sha256')
                        }
                    }
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {str(e)}")
        return True
    
    def compare_with_baseline(self, baseline_file):
        """Compare current state with baseline"""
        try:
            with open(baseline_file) as f:
                baseline = json.load(f)
            
            findings = []
            baseline_files = baseline.get('files', {})
            
            for path, current in self.file_hashes.items():
                if path in baseline_files:
                    baseline_info = baseline_files[path]
                    if current['hashes']['sha256'] != baseline_info['hashes'].get('sha256'):
                        findings.append({
                            'type': 'MODIFIED',
                            'file': path,
                            'algorithm': 'sha256',
                            'baseline_hash': baseline_info['hashes'].get('sha256'),
                            'current_hash': current['hashes'].get('sha256'),
                            'baseline_size': baseline_info['size'],
                            'current_size': current['size']
                        })
                    elif current['size'] != baseline_info['size']:
                        findings.append({
                            'type': 'SIZE_CHANGE',
                            'file': path,
                            'baseline_size': baseline_info['size'],
                            'current_size': current['size']
                        })
            
            # Find new and deleted files
            findings.extend(
                {'type': 'NEW_FILE', 'file': p, 'hashes': info['hashes']} 
                for p, info in self.file_hashes.items() if p not in baseline_files
            )
            findings.extend(
                {'type': 'DELETED', 'file': p, 'baseline_info': baseline_files[p]} 
                for p in baseline_files if p not in self.file_hashes
            )
            
            self.findings = findings
            return findings
        except Exception as e:
            logging.error(f"Comparison error: {str(e)}")
            return None
    
    def save_baseline(self, output_file):
        """Save current state as baseline"""
        try:
            os.makedirs('baselines', exist_ok=True)
            with open(os.path.join('baselines', output_file), 'w') as f:
                json.dump({
                    'scan_time': self.scan_time,
                    'files': self.file_hashes
                }, f, indent=2)
            return True
        except Exception as e:
            logging.error(f"Save error: {str(e)}")
            return False
    
    def check_virustotal(self, file_path, api_key):
        """Check file against VirusTotal API"""
        try:
            # First try hash lookup
            file_hash = self.file_hashes[file_path]['hashes']['sha256']
            headers = {'x-apikey': api_key}
            
            # Hash lookup
            response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                if data.get('last_analysis_stats', {}).get('malicious', 0) > 0:
                    return data
            
            # If not found, upload the file (for files <32MB)
            if os.path.getsize(file_path) < 32 * 1024 * 1024:
                with open(file_path, 'rb') as f:
                    response = requests.post(
                        'https://www.virustotal.com/api/v3/files',
                        headers=headers,
                        files={'file': f},
                        timeout=30
                    )
                if response.status_code == 200:
                    return response.json().get('data', {}).get('attributes', {})
            
            return None
        except Exception as e:
            logging.error(f"VirusTotal API error for {file_path}: {str(e)}")
            return None
    
    def check_suspicious_files(self, api_key=None, scan_all=False):
        """Check files against VirusTotal"""
        if not api_key:
            api_key = get_virustotal_api_key()
            if not api_key:
                logging.warning("No VirusTotal API key available")
                return []

        suspicious = []
        for file_path in self.file_hashes:
            try:
                result = self.check_virustotal(file_path, api_key)
                if result and result.get('last_analysis_stats', {}).get('malicious', 0) > 0:
                    stats = result['last_analysis_stats']
                    suspicious.append({
                        'type': 'MALICIOUS',
                        'file': file_path,
                        'detections': f"{stats['malicious']}/{stats['malicious'] + stats['harmless']}",
                        'hash': self.file_hashes[file_path]['hashes']['sha256'],
                        'vendors': {
                            k: v['result']
                            for k, v in result.get('last_analysis_results', {}).items()
                            if v['category'] == 'malicious'
                        }
                    })
            except Exception as e:
                logging.error(f"Error scanning {file_path}: {str(e)}")
        
        self.findings.extend(suspicious)
        return suspicious

# Helper functions
def get_virustotal_api_key():
    """Get API key from config"""
    config = ConfigParser()
    config.read('config.ini')
    return config.get('VIRUSTOTAL', 'api_key', fallback=None)

def save_virustotal_api_key(api_key):
    """Save API key to config"""
    config = ConfigParser()
    config['VIRUSTOTAL'] = {'api_key': api_key}
    with open('config.ini', 'w') as f:
        config.write(f)

def create_baseline():
    path = input("Enter directory to scan: ").strip()
    if not path:
        print("Error: Path cannot be empty")
        return
    
    scanner = FileIntegrityScanner()
    if scanner.scan_directory(path):
        filename = f"baseline_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        if scanner.save_baseline(filename):
            print(f"Successfully created baseline: baselines/{filename}")
        else:
            print("Failed to save baseline")

def compare_baseline():
    baselines = [f for f in os.listdir('baselines') if f.endswith('.json')]
    if not baselines:
        print("No baselines found in 'baselines' directory")
        return
    
    print("\nAvailable baselines:")
    for i, baseline in enumerate(sorted(baselines), 1):
        print(f"{i}. {baseline}")
    
    try:
        selection = int(input("\nSelect baseline to compare against (number): "))
        if selection < 1 or selection > len(baselines):
            raise ValueError
    except ValueError:
        print("Invalid selection")
        return
    
    baseline_file = os.path.join('baselines', baselines[selection-1])
    path = input("\nEnter directory path to scan: ").strip()
    
    if not path:
        print("Error: Path cannot be empty")
        return
    if not os.path.isdir(path):
        print("Error: Path must be a directory")
        return
    
    scanner = FileIntegrityScanner()
    if scanner.scan_directory(path):
        if findings := scanner.compare_with_baseline(baseline_file):
            print(f"\nFound {len(findings)} integrity violations")
            if input("Generate PDF report? (y/n): ").lower() == 'y':
                report_path = create_pdf_report(scanner.findings)
                print(f"PDF report generated: {report_path}")
        else:
            print("\nNo integrity violations found")

def automatic_threat_scan():
    print("\n=== AUTOMATIC THREAT SCAN ===")
    if not (api_key := get_virustotal_api_key()):
        if not (api_key := input("Enter VirusTotal API key: ").strip()):
            return
        save_virustotal_api_key(api_key)
    
    try:
        baselines = sorted(f for f in os.listdir('baselines') if f.endswith('.json'))
        if not baselines:
            print("No baselines found")
            return
        
        latest = os.path.join('baselines', baselines[-1])
        with open(latest) as f:
            scan_path = os.path.dirname(next(iter(json.load(f)['files'].values()))['path'])
        
        print(f"\nScanning: {scan_path}")
        scanner = FileIntegrityScanner()
        if scanner.scan_directory(scan_path):
            scanner.compare_with_baseline(latest)
            scanner.check_suspicious_files(api_key, scan_all=True)
            
            if scanner.findings:
                print(f"\nFound {len(scanner.findings)} security issues:")
                for finding in scanner.findings:
                    if finding['type'] == 'MALICIOUS_FILE':
                        print(f"- Malicious: {finding['file']}")
                        print(f"  Detections: {finding['detections']}")
                report_path = create_pdf_report(scanner.findings)
                print(f"\nPDF report generated: {report_path}")
            else:
                print("No security issues found")
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        logging.error(f"Scan error: {str(e)}", exc_info=True)

def main():
    os.makedirs('baselines', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    if not os.path.exists('config.ini'):
        with open('config.ini', 'w') as f:
            f.write("[VIRUSTOTAL]\napi_key = \n")
    
    while True:
        print("\n=== File Integrity Toolkit ==="
              "\n1. Create baseline\n2. Compare\n3. Auto threat scan\n4. Exit")
        choice = input("Choice (1-4): ")
        
        if choice == '1':
            create_baseline()
        elif choice == '2':
            compare_baseline()
        elif choice == '3':
            automatic_threat_scan()
        elif choice == '4':
            print("Exiting File Integrity Toolkit")
            break
        else:
            print("Invalid choice")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
