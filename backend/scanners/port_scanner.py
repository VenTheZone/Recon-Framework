import nmap

def run_port_scanner(target):
    """
    Performs a port scan on the given target.
    """
    nm = nmap.PortScanner()
    nm.scan(target, '22-443')
    scan_results = []
    for host in nm.all_hosts():
        host_results = {'host': host, 'ports': []}
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = {
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                }
                host_results['ports'].append(port_info)
        scan_results.append(host_results)
    return scan_results
