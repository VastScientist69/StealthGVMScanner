from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
import xml.etree.ElementTree as ET
import time
import random
import re
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import ipaddress
import socket

# 1. Define connection parameters with enhanced stealth
path = '/run/gvmd/gvmd.sock'
connection = UnixSocketConnection(path=path)
transform = EtreeTransform()

# Stealth configuration
STEALTH_CONFIG = {
    'min_delay': 2,          # Minimum delay between operations (seconds)
    'max_delay': 8,          # Maximum delay between operations (seconds)
    'jitter_factor': 0.3,    # Random jitter to add to timing
    'scan_time_variation': 0.2,  # Variation in scan timing patterns
    'max_parallel_tasks': 3, # Maximum simultaneous scan tasks
}

# 2. Authenticate with the GMP protocol
username = 'admin'
password = 'your_secure_password'

def stealth_delay(min_time=None, max_time=None):
    """Add randomized delay to mimic human behavior and avoid detection"""
    min_time = min_time or STEALTH_CONFIG['min_delay']
    max_time = max_time or STEALTH_CONFIG['max_delay']
    
    base_delay = random.uniform(min_time, max_time)
    jitter = base_delay * random.uniform(-STEALTH_CONFIG['jitter_factor'], 
                                        STEALTH_CONFIG['jitter_factor'])
    total_delay = max(0.5, base_delay + jitter)
    time.sleep(total_delay)

def get_or_create_target(gmp, target_name, target_hosts, port_list_id, 
                         exclude_hosts=None, stealth_scan=True):
    """Get existing target or create a new one with stealth options"""
    # Try to find existing target first
    try:
        targets_xml = gmp.get_targets(filter_string=f"rows=-1 details=1")
        for target in targets_xml.findall('target'):
            name = target.find('name').text
            if name == target_name:
                return target.get('id')
    except Exception as e:
        print(f"Error checking existing targets: {e}")
    
    # Create new target with stealth options
    target_config = {
        'name': target_name,
        'hosts': target_hosts,
        'port_list_id': port_list_id,
    }
    
    if exclude_hosts:
        target_config['exclude_hosts'] = exclude_hosts
    
    if stealth_scan:
        # Configure for stealthier scanning
        target_config['alive_tests'] = 'ICMP, TCP-ACK Service'  # More stealthy than ARP
        target_config['reverse_lookup_only'] = '0'  # Don't do reverse DNS lookup
        target_config['reverse_lookup_unify'] = '0'  # Don't unify hosts by reverse DNS
    
    target_id = gmp.create_target(**target_config).get('id')
    stealth_delay()
    return target_id

def get_task_report_id(gmp, task_id):
    """Get the report ID for a completed task with error handling"""
    try:
        tasks_xml = gmp.get_tasks(filter_string=f"rows=-1 details=1")
        for task in tasks_xml.findall('task'):
            if task.get('id') == task_id:
                status = task.find('status').text
                if status == 'Done':
                    report = task.find('last_report/report')
                    if report is not None and 'id' in report.attrib:
                        return report.get('id')
                elif status in ['Stop Requested', 'Stopped', 'Interrupted']:
                    print(f"Task {task_id} was stopped or interrupted")
                    return None
                elif status == 'New':
                    print(f"Task {task_id} hasn't started yet")
                    return None
                else:
                    # Task is still running
                    return None
    except Exception as e:
        print(f"Error getting task status: {e}")
        stealth_delay(5, 10)  # Longer delay on error
    return None

def parse_and_summarize_report(report_xml, min_severity=0.0, output_format='text'):
    """Parse the XML report and extract vulnerabilities with filtering options"""
    try:
        # Namespace handling for XML parsing
        ns = {'nvt': 'http://openvas.org/nvt'}
        ET.register_namespace('', 'http://openvas.org/nvt')
        
        results = []
        for result in report_xml.findall('.//result'):
            # Extract severity
            severity_elem = result.find('severity')
            severity = float(severity_elem.text) if severity_elem is not None and severity_elem.text else 0.0
            
            if severity < min_severity:
                continue
                
            # Extract details
            name_elem = result.find('name')
            name = name_elem.text if name_elem is not None else 'N/A'
            
            host_elem = result.find('host')
            host = host_elem.text if host_elem is not None else 'N/A'
            
            port_elem = result.find('port')
            port = port_elem.text if port_elem is not None else 'N/A'
            
            # Extract NVT details
            nvt_elem = result.find('nvt')
            if nvt_elem is not None:
                oid = nvt_elem.get('oid', 'N/A')
                
                # Try to extract CVSS score
                cvss_base_elem = nvt_elem.find('nvt:cvss_base', ns)
                cvss_base = cvss_base_elem.text if cvss_base_elem is not None else 'N/A'
                
                # Try to extract CVE references
                cves = []
                refs_elem = nvt_elem.find('nvt:references', ns)
                if refs_elem is not None:
                    for ref in refs_elem.findall('nvt:reference', ns):
                        ref_type = ref.get('type', '')
                        if ref_type == 'cve':
                            cves.append(ref.get('id', ''))
            else:
                oid = 'N/A'
                cvss_base = 'N/A'
                cves = []
            
            # Extract description
            description_elem = result.find('description')
            description = description_elem.text if description_elem is not None else 'N/A'
            
            # Extract solution if available
            solution_elem = result.find('solution')
            solution = solution_elem.text if solution_elem is not None else 'No solution provided'
            
            results.append({
                'name': name,
                'host': host,
                'port': port,
                'severity': severity,
                'oid': oid,
                'cvss_base': cvss_base,
                'cves': cves,
                'description': description,
                'solution': solution
            })
        
        # Sort by severity (highest first)
        results.sort(key=lambda x: x['severity'], reverse=True)
        
        # Generate output based on format
        if output_format == 'json':
            return json.dumps(results, indent=2)
        elif output_format == 'csv':
            output = "Name,Host,Port,Severity,CVSS Base,CVE IDs,Description,Solution\n"
            for result in results:
                output += f"\"{result['name']}\",\"{result['host']}\",\"{result['port']}\",{result['severity']},\"{result['cvss_base']}\",\"{','.join(result['cves'])}\",\"{result['description']}\",\"{result['solution']}\"\n"
            return output
        else:  # text format
            output = f"Vulnerability Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            output += "=" * 80 + "\n\n"
            
            for i, result in enumerate(results, 1):
                output += f"{i}. {result['name']}\n"
                output += f"   Host: {result['host']}:{result['port']}\n"
                output += f"   Severity: {result['severity']} (CVSS: {result['cvss_base']})\n"
                if result['cves']:
                    output += f"   CVE IDs: {', '.join(result['cves'])}\n"
                output += f"   Description: {result['description']}\n"
                output += f"   Solution: {result['solution']}\n\n"
            
            # Add summary
            output += "SUMMARY:\n"
            output += f"Total vulnerabilities found: {len(results)}\n"
            if results:
                severity_counts = {
                    'Critical': len([r for r in results if r['severity'] >= 9.0]),
                    'High': len([r for r in results if 7.0 <= r['severity'] < 9.0]),
                    'Medium': len([r for r in results if 4.0 <= r['severity'] < 7.0]),
                    'Low': len([r for r in results if 0.1 <= r['severity'] < 4.0]),
                    'Info': len([r for r in results if r['severity'] == 0.0]),
                }
                output += f"Critical: {severity_counts['Critical']}\n"
                output += f"High: {severity_counts['High']}\n"
                output += f"Medium: {severity_counts['Medium']}\n"
                output += f"Low: {severity_counts['Low']}\n"
                output += f"Info: {severity_counts['Info']}\n"
            
            return output
            
    except Exception as e:
        return f"Error parsing report: {str(e)}"

def obfuscate_targets(targets):
    """Obfuscate target list to avoid pattern detection"""
    obfuscated = []
    for target in targets:
        # If it's a CIDR range, sometimes break it into smaller chunks
        if '/' in target and random.random() < 0.3:  # 30% chance to break up
            try:
                network = ipaddress.ip_network(target, strict=False)
                # Split into smaller subnets randomly
                if network.prefixlen <= 28:  # Only split larger networks
                    new_prefix = random.randint(network.prefixlen + 2, min(30, network.prefixlen + 6))
                    subnets = list(network.subnets(new_prefix=new_prefix))
                    # Randomly select some subnets
                    selected = random.sample(subnets, k=random.randint(1, min(3, len(subnets))))
                    obfuscated.extend(str(subnet) for subnet in selected)
                    continue
            except:
                pass  # If anything fails, just use the original target
        
        obfuscated.append(target)
    
    return obfuscated

def create_stealth_scan_config(gmp, config_name):
    """Create a custom stealth scan configuration"""
    # Clone the "Full and Fast" config as a base
    base_config_id = 'daba56c8-73ec-11df-a475-002264764cea'
    
    # Get the base config
    base_config = gmp.get_config(config_id=base_config_id)
    
    # Create a new config with stealth settings
    new_config_id = gmp.create_config(
        name=config_name,
        base=base_config_id
    ).get('id')
    
    stealth_delay()
    
    # Modify settings for stealth (this is a simplified example)
    # In a real implementation, you would modify specific NVT preferences
    
    return new_config_id

def main():
    """Main scanning function with enhanced stealth and power"""
    try:
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(username, password)
            stealth_delay()

            # 3. Get or create a target with stealth options
            target_name = 'Network Assessment'
            base_targets = ['192.168.1.0/24']  # Example: scanning a subnet
            port_list_id = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'  # Default "All IANA assigned" list
            
            # Obfuscate targets to avoid pattern detection
            obfuscated_targets = obfuscate_targets(base_targets)
            print(f"Scanning targets: {obfuscated_targets}")
            
            target_id = get_or_create_target(
                gmp, 
                target_name, 
                obfuscated_targets, 
                port_list_id,
                stealth_scan=True
            )
            stealth_delay()

            # 4. Get or create a scan configuration
            # For stealth, we could create a custom config, but using Full and Fast for simplicity
            config_id = 'daba56c8-73ec-11df-a475-002264764cea'  # ID for "Full and Fast"

            # 5. Get a scanner
            scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'  # Default OpenVAS scanner

            # 6. Create a task with randomized name
            task_id = f"scan_{random.randint(10000, 99999)}"
            task_name = f'System Audit {task_id}'
            
            task_id = gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id
            ).get('id')
            stealth_delay()

            # 7. Start the task
            gmp.start_task(task_id)
            print(f"Started task {task_name} with ID {task_id}")
            stealth_delay(3, 6)

            # 8. Monitor the task status with randomized checking intervals
            print("Monitoring scan progress...")
            scan_start_time = time.time()
            last_check = scan_start_time
            check_intervals = []
            
            while True:
                current_time = time.time()
                elapsed = current_time - last_check
                
                # Vary the check interval randomly
                min_interval = 30  # Minimum 30 seconds between checks
                max_interval = 90  # Maximum 90 seconds between checks
                check_interval = random.uniform(min_interval, max_interval)
                
                if elapsed >= check_interval:
                    report_id = get_task_report_id(gmp, task_id)
                    if report_id:
                        break
                    
                    # Print status with random variations
                    status_messages = [
                        "Scan in progress...",
                        "Analyzing network services...",
                        "Checking system vulnerabilities...",
                        "Security assessment ongoing...",
                        "Network probe active..."
                    ]
                    print(random.choice(status_messages))
                    
                    last_check = current_time
                    check_intervals.append(check_interval)
                    
                    # Calculate average interval and adjust for more realistic behavior
                    if len(check_intervals) > 3:
                        avg_interval = sum(check_intervals[-3:]) / 3
                        min_interval = max(20, avg_interval * 0.7)
                        max_interval = min(120, avg_interval * 1.3)
                
                # Sleep with some randomness
                time.sleep(random.uniform(5, 15))
            
            scan_duration = time.time() - scan_start_time
            print(f"Scan completed in {scan_duration:.2f} seconds")
            stealth_delay()

            # 9. Get the report in XML format
            report_xml = gmp.get_report(report_id, report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5')
            stealth_delay()

            # 10. Parse and display the report with different output options
            print("\n" + "="*80)
            print("SCAN RESULTS SUMMARY")
            print("="*80)
            
            # Display text summary
            text_report = parse_and_summarize_report(report_xml, min_severity=0.1, output_format='text')
            print(text_report)
            
            # Also save detailed reports in multiple formats
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Save JSON report
            json_report = parse_and_summarize_report(report_xml, min_severity=0.0, output_format='json')
            with open(f'scan_report_{timestamp}.json', 'w') as f:
                f.write(json_report)
            
            # Save CSV report
            csv_report = parse_and_summarize_report(report_xml, min_severity=0.0, output_format='csv')
            with open(f'scan_report_{timestamp}.csv', 'w') as f:
                f.write(csv_report)
                
            print(f"\nDetailed reports saved as:")
            print(f"  - scan_report_{timestamp}.json")
            print(f"  - scan_report_{timestamp}.csv")
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        # Add extra delay on error to avoid rapid retry patterns
        time.sleep(random.uniform(10, 20))

if __name__ == '__main__':
    main()
