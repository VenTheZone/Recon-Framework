import socket
import dns.resolver

def run_surface_scanner(domain):
    """
    Performs a basic subdomain enumeration for the given domain.
    """
    subdomains = []
    wordlist = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "admin"
    ]

    for subdomain in wordlist:
        full_domain = f"{subdomain}.{domain}"
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            for ip in answers:
                subdomains.append({'domain': full_domain, 'ip': ip.to_text()})
                print(f"[+] Found subdomain: {full_domain} ({ip.to_text()})")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

    # Also try to get other common record types for the main domain
    records = {}
    for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [r.to_text() for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

    return {'subdomains': subdomains, 'records': records}
