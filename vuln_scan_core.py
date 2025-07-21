# vuln_scan_core.py
# Core logic for VulnScan Reporter: Nmap scanning, analysis, and report generation.

import nmap
import sys
import datetime # For better timestamping

def run_nmap_scan(target_ip_range, nm_scanner, scan_options):
    """
    Runs an Nmap scan with selected options.
    
    Args:
        target_ip_range (str): The IP address or range to scan.
        nm_scanner (nmap.PortScanner): An initialized nmap.PortScanner object.
        scan_options (dict): Dictionary of boolean flags for scan types.
            e.g., {'aggressive': True, 'all_ports': False, 'vuln_scripts': False}
        
    Returns:
        list: A list of IP addresses of hosts that were scanned.
    """
    arguments = []

    # Base arguments for service and default script detection
    arguments.append('-sV') # Service version detection
    arguments.append('-sC') # Default NSE scripts

    # Add aggressive scan (-A) which includes OS detection, version detection, script scanning, and traceroute
    if scan_options.get('aggressive'):
        arguments.append('-A')
        print("[*] Aggressive scan (-A) enabled.")
    
    # Scan all 65535 ports (-p-) - WARNING: This can be very slow!
    if scan_options.get('all_ports'):
        arguments.append('-p-')
        print("[*] Scanning all 65535 ports (-p-) enabled. This will take a long time!")

    # Run all vulnerability scripts (--script=vuln) - WARNING: This can be very slow and noisy!
    if scan_options.get('vuln_scripts'):
        arguments.append('--script=vuln')
        print("[*] Running Nmap vulnerability scripts (--script=vuln) enabled. This will take a very long time and generate extensive output!")

    # Add discovery scripts
    if scan_options.get('discovery_scripts'):
        arguments.append('--script=discovery')
        print("[*] Running Nmap discovery scripts enabled.")

    # Add safe scripts
    if scan_options.get('safe_scripts'):
        arguments.append('--script=safe')
        print("[*] Running Nmap safe scripts enabled.")

    # Set a faster timing template (T4 is generally good, T5 is more aggressive)
    arguments.append('-T4') 

    full_arguments_str = ' '.join(arguments)
    print(f"[*] Starting Nmap scan on {target_ip_range} with arguments: {full_arguments_str}")
    
    try:
        # The nm_scanner object will be populated after this call with scan results
        nm_scanner.scan(hosts=target_ip_range, arguments=full_arguments_str)
        print("[*] Nmap scan completed.")
        return nm_scanner.all_hosts() # Returns a list of scanned hosts
    except nmap.PortScannerError as e:
        print(f"[-] Nmap scan error: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[-] An unexpected error occurred during Nmap scan: {e}", file=sys.stderr)
        return []

def analyze_scan_results(scanned_hosts, nm_scanner):
    """
    Analyzes Nmap scan results from the nm_scanner object and extracts key information.
    
    Args:
        scanned_hosts (list): A list of IP addresses of hosts that were scanned.
        nm_scanner (nmap.PortScanner): The nmap.PortScanner object containing the scan results.
        
    Returns:
        dict: A structured dictionary where keys are IP addresses and values are host findings.
    """
    findings = {}
    for host in scanned_hosts:
        if host not in nm_scanner.all_hosts():
            continue

        host_info = {
            'ip_address': host,
            'hostname': nm_scanner[host].hostname(),
            'state': nm_scanner[host].state(),
            'os_match': [], # For OS detection
            'ports': []
        }

        # Get OS detection results if available (from -A scan)
        if 'osmatch' in nm_scanner[host]:
            for os_match in nm_scanner[host]['osmatch']:
                host_info['os_match'].append({
                    'name': os_match['name'],
                    'accuracy': os_match['accuracy']
                })

        # Process TCP ports
        if 'tcp' in nm_scanner[host]:
            for port in nm_scanner[host]['tcp']:
                port_info = {
                    'port_id': port,
                    'protocol': 'tcp',
                    'state': nm_scanner[host]['tcp'][port]['state'],
                    'service': nm_scanner[host]['tcp'][port]['name'],
                    'product': nm_scanner[host]['tcp'][port]['product'],
                    'version': nm_scanner[host]['tcp'][port]['version'],
                    'extrainfo': nm_scanner[host]['tcp'][port]['extrainfo'],
                    'scripts': {}
                }
                if 'script' in nm_scanner[host]['tcp'][port]:
                    for script_name, script_output in nm_scanner[host]['tcp'][port]['script'].items():
                        port_info['scripts'][script_name] = script_output
                host_info['ports'].append(port_info)
        
        # Process UDP ports
        if 'udp' in nm_scanner[host]:
            for port in nm_scanner[host]['udp']:
                port_info = {
                    'port_id': port,
                    'protocol': 'udp',
                    'state': nm_scanner[host]['udp'][port]['state'],
                    'service': nm_scanner[host]['udp'][port]['name'],
                    'product': nm_scanner[host]['udp'][port]['product'],
                    'version': nm_scanner[host]['udp'][port]['version'],
                    'extrainfo': nm_scanner[host]['udp'][port]['extrainfo'],
                    'scripts': {}
                }
                if 'script' in nm_scanner[host]['udp'][port]:
                    for script_name, script_output in nm_scanner[host]['udp'][port]['script'].items():
                        port_info['scripts'][script_name] = script_output
                host_info['ports'].append(port_info)

        findings[host] = host_info
    return findings

def get_recommendation(script_name, script_output):
    """
    Provides a specific recommendation based on Nmap script output.
    """
    clean_output = script_output.strip().lower()
    
    if 'vulnerable' in clean_output or 'exploit' in clean_output or 'weak' in clean_output:
        return "🚨 **Critical Vulnerability Detected!** Investigate and patch immediately."
    elif 'anonymous login' in clean_output and 'ftp' in script_name:
        return "⚠️ **Anonymous FTP Access:** Disable unless explicitly required and secured. This is a significant risk."
    elif 'ssh-hostkey' in script_name:
        return "💡 **SSH Configuration:** Ensure SSH keys are properly managed, strong passwords are enforced, and root login is disabled if not needed."
    elif 'http-server-header' in script_name and ('nginx' in clean_output or 'apache' in clean_output):
        return "ℹ️ **Information Disclosure:** Consider hiding server banners to prevent attackers from easily identifying software versions."
    elif 'mysql-info' in script_name:
        return "💡 **MySQL Security:** Review MySQL user accounts and permissions. Ensure strong passwords for all users, especially 'root'."
    elif 'smb-enum-shares' in script_name or 'smb-enum-users' in clean_output:
        return "⚠️ **SMB Information Leakage:** Sensitive SMB shares or user lists exposed. Restrict access and review share permissions."
    elif 'default credentials' in clean_output:
        return "🚨 **Default Credentials:** Change default credentials immediately for this service."
    elif 'outdated' in clean_output or 'unpatched' in clean_output:
        return "⚠️ **Outdated Software:** Update or patch this service to the latest version to address known vulnerabilities."
    elif 'ssl-enum-ciphers' in script_name and ('weak ciphers' in clean_output or 'vulnerable' in clean_output or 'deprecated' in clean_output):
        return "⚠️ **Weak SSL/TLS Configuration:** Configure stronger SSL/TLS ciphers and protocols. Disable older, insecure versions like SSLv2/v3, TLSv1.0/1.1."
    elif 'dns-recursion' in script_name and 'recursion desired' in clean_output:
        return "⚠️ **Open DNS Recursion:** Your DNS server appears to allow open recursion, which can be abused for DDoS attacks. Restrict recursion to trusted clients only."
    
    return None # No specific recommendation

def generate_report(findings, nm_scanner):
    """
    Generates a human-readable report in Markdown format from the analyzed findings,
    including a summary and improved formatting.
    
    Args:
        findings (dict): The structured dictionary of scan findings.
        nm_scanner (nmap.PortScanner): The nmap.PortScanner object containing the scan results.
        
    Returns:
        str: The complete report content as a Markdown string.
    """
    report_content = []
    
    # --- Report Header ---
    report_content.append("# 🛡️ VulnScan Reporter - Comprehensive Scan Report\n")
    report_content.append(f"**Scan Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Attempt to get Nmap scan statistics for more details
    try:
        nm_stats = nm_scanner.scanstats()
        report_content.append(f"**Scan Duration:** {nm_stats.get('elapsed', 'N/A')} seconds\n")
        report_content.append(f"**Nmap Command:** `{nm_stats.get('command_line', 'N/A')}`\n")
    except Exception:
        report_content.append("**Scan Statistics:** Not available (Nmap scan may have failed or no hosts were found).\n")
    
    report_content.append("---\n\n")

    # --- Summary Section ---
    total_hosts_scanned = len(findings)
    up_hosts = sum(1 for host_info in findings.values() if host_info['state'] == 'up')
    open_ports_count = sum(len(host_info['ports']) for host_info in findings.values())
    
    report_content.append("## 📊 Scan Summary\n")
    report_content.append(f"- **Total Hosts Scanned:** {total_hosts_scanned}\n")
    report_content.append(f"- **Hosts Found Online:** {up_hosts}\n")
    report_content.append(f"- **Total Open Ports Detected:** {open_ports_count}\n")
    report_content.append("\n---\n\n")

    if not findings:
        report_content.append("### No Active Hosts Found\n")
        report_content.append("No active hosts or open ports were found in the specified range. "
                              "This could mean the target is offline, firewalled, or the IP range is incorrect. "
                              "Please ensure target VMs are running and on the correct network.\n")
        return "\n".join(report_content)

    report_content.append("## 🖥️ Host Details & Findings\n")

    for ip, info in findings.items():
        report_content.append(f"### Host: `{info['ip_address']}`")
        if info['hostname']:
            report_content.append(f" (`{info['hostname']}`)")
        report_content.append(f"\n**Status:** {info['state'].capitalize()}\n")

        if info['os_match']:
            report_content.append("\n**Operating System Guesses:**\n")
            for os_match in info['os_match']:
                report_content.append(f"- {os_match['name']} (Accuracy: {os_match['accuracy']}%)\n")

        if info['ports']:
            report_content.append("\n#### Open Ports & Services:\n")
            for port in info['ports']:
                report_content.append(f"- **Port:** `{port['port_id']}/{port['protocol']}` | **State:** `{port['state']}` | **Service:** `{port['service']}`")
                if port['product']:
                    report_content.append(f" **Product:** `{port['product']}`")
                if port['version']:
                    report_content.append(f" **Version:** `{port['version']}`")
                if port['extrainfo']:
                    report_content.append(f" **Extra Info:** `{port['extrainfo']}`")
                report_content.append("\n")

                if port['scripts']:
                    report_content.append("  **NSE Script Output / Potential Issues:**\n")
                    for script_name, script_output in port['scripts'].items():
                        # Clean up and format script output for readability
                        clean_output_display = script_output.strip().replace('\n', ' ').replace('  ', ' ')
                        report_content.append(f"    - **`{script_name}`:** `{clean_output_display}`\n")
                        
                        # Add specific recommendations
                        recommendation = get_recommendation(script_name, script_output)
                        if recommendation:
                            report_content.append(f"      {recommendation}\n")

            report_content.append("\n")
        else:
            report_content.append("No open ports found on this host.\n\n")
        report_content.append("---\n\n") 
        
    return "\n".join(report_content)

# This block is for testing this module directly, not used when imported by Streamlit
if __name__ == "__main__":
    # Example usage: Replace with your Ubuntu-Target VM's IP
    target_range = '192.168.100.11' 
    
    # Example scan options for direct testing
    test_scan_options = {
        'aggressive': True, 
        'all_ports': False, 
        'vuln_scripts': False,
        'discovery_scripts': True,
        'safe_scripts': True
    }

    nm = nmap.PortScanner() 
    scanned_hosts = run_nmap_scan(target_range, nm, test_scan_options) # Pass scan_options
    findings = analyze_scan_results(scanned_hosts, nm)
    report = generate_report(findings, nm) # Pass nm_scanner
    
    report_filename = "vuln_scan_report.md"
    try:
        with open(report_filename, "w") as f:
            f.write(report)
        print(f"[*] Report saved to {report_filename}")
    except IOError as e:
        print(f"[-] Error saving report to file: {e}", file=sys.stderr)
