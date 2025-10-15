from weasyprint import HTML
import re
import json

def generate_html_report(scan):
    if scan.scan_type == 'bypass':
        report_data = {
            'bypassed_urls': re.findall(r'\[SUCCESS\].*?(http[s]?://[^\s|]+)', scan.result),
            'enhanced_bypassed_urls': re.findall(r'\[ENHANCED SUCCESS\].*?(http[s]?://[^\s|]+)', scan.result),
            'different_403s': re.findall(r'\[(?:DIFFERENT|ENHANCED DIFFERENT) 403\].*?(http[s]?://[^\s]+)', scan.result),
            'found_endpoints': re.findall(r'\[FOUND\].*?(http[s]?://[^\s]+)', scan.result),
            'vulnerabilities': re.findall(r'\[VULNERABLE\].*?(http[s]?://[^\s]+)', scan.result),
            'findings': re.findall(r'\[FINDING\].*', scan.result),
        }

        html = f"""
        <html>
        <head>
            <title>Scan Report for {scan.url}</title>
            <style>
                body {{ font-family: sans-serif; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; }}
                ul {{ list-style-type: none; padding: 0; }}
                li {{ padding: 5px; margin-bottom: 2px; }}
                .success {{ background-color: #d4edda; }}
                .warning {{ background-color: #fff3cd; }}
                .danger {{ background-color: #f8d7da; }}
                .info {{ background-color: #d1ecf1; }}
            </style>
        </head>
        <body>
            <h1>Bypass Scan Report for {scan.url}</h1>
            <h2>Successfully Bypassed ({len(report_data['bypassed_urls'])}):</h2>
            <ul>{''.join(f'<li class="success">{url}</li>' for url in report_data['bypassed_urls'])}</ul>
            <h2>Enhanced Bypass Success ({len(report_data['enhanced_bypassed_urls'])}):</h2>
            <ul>{''.join(f'<li class="success">{url}</li>' for url in report_data['enhanced_bypassed_urls'])}</ul>
            <h2>Interesting 403s ({len(report_data['different_403s'])}):</h2>
            <ul>{''.join(f'<li class="warning">{url}</li>' for url in report_data['different_403s'])}</ul>
            <h2>Found Endpoints ({len(report_data['found_endpoints'])}):</h2>
            <ul>{''.join(f'<li class="info">{url}</li>' for url in report_data['found_endpoints'])}</ul>
            <h2>Vulnerabilities Found ({len(report_data['vulnerabilities'])}):</h2>
            <ul>{''.join(f'<li class="danger">{url}</li>' for url in report_data['vulnerabilities'])}</ul>
            <h2>Other Findings ({len(report_data['findings'])}):</h2>
            <ul>{''.join(f'<li>{finding}</li>' for finding in report_data['findings'])}</ul>
        </body>
        </html>
        """
    elif scan.scan_type == 'xss':
        html = f"""
        <html>
        <head>
            <title>XSS Scan Report for {scan.url}</title>
        </head>
        <body>
            <h1>XSS Scan Report for {scan.url}</h1>
            <p>Result: {scan.result}</p>
        </body>
        </html>
        """
    elif scan.scan_type == 'surface':
        data = json.loads(scan.result)
        subdomains = data.get('subdomains', [])
        records = data.get('records', {})
        html = f"""
        <html>
        <head>
            <title>Attack Surface Report for {scan.url}</title>
        </head>
        <body>
            <h1>Attack Surface Report for {scan.url}</h1>
            <h2>Found Subdomains ({len(subdomains)}):</h2>
            <ul>{''.join(f'<li>{subdomain["domain"]} ({subdomain["ip"]})</li>' for subdomain in subdomains)}</ul>
            <h2>DNS Records:</h2>
            <ul>{''.join(f'<li><b>{rectype}:</b> {", ".join(rec)}</li>' for rectype, rec in records.items())}</ul>
        </body>
        </html>
        """
    else:
        html = f"""
        <html>
        <head>
            <title>Scan Report for {scan.url}</title>
        </head>
        <body>
            <h1>Scan Report for {scan.url}</h1>
            <p>Result: {scan.result}</p>
        </body>
        </html>
        """
    return html

def generate_pdf_report(scan):
    html_report = generate_html_report(scan)
    return HTML(string=html_report).write_pdf()
