from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os
import logging

def create_pdf_report(findings):
    """Generate a clean, professional PDF report"""
    try:
        os.makedirs('reports', exist_ok=True)
        timestamp = datetime.now()
        
        # Prepare report data
        report_data = {
            'report_date': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'findings': process_findings(findings),
            'finding_count': len(findings),
            'finding_stats': {
                'modified': sum(1 for f in findings if f['type'] in ['MODIFIED', 'SIZE_CHANGE']),
                'new': sum(1 for f in findings if f['type'] == 'NEW_FILE'),
                'deleted': sum(1 for f in findings if f['type'] == 'DELETED'),
                'suspicious': sum(1 for f in findings if f['type'] == 'MALICIOUS')
            }
        }

        # Setup template environment
        env = Environment(loader=FileSystemLoader('templates'))
        
        # Render HTML
        template = env.get_template('forensic_report.html')
        html_content = template.render(report_data)
        
        # Generate PDF
        report_filename = f"forensic_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
        report_path = os.path.join('reports', report_filename)
        
        HTML(string=html_content).write_pdf(
            report_path,
            stylesheets=None,  # Using embedded CSS
            presentational_hints=True
        )
        
        logging.info(f"PDF report generated: {report_path}")
        return report_path
        
    except Exception as e:
        logging.error(f"Failed to generate PDF report: {str(e)}")
        return None

def process_findings(findings):
    """Format findings for the template"""
    processed = []
    for finding in findings:
        entry = {
            'type': finding['type'].replace('_', ' '),
            'file': finding.get('file', ''),
            'details': {}
        }
        
        if finding['type'] == 'MALICIOUS':
            entry['type'] = 'SUSPICIOUS FILE'
            entry['details'] = {
                'threat_info': {
                    'positives': finding.get('detections', '0/0').split('/')[0],
                    'total': finding.get('detections', '0/0').split('/')[1]
                },
                'hash': finding.get('hash', '')
            }
        
        processed.append(entry)
    return processed
