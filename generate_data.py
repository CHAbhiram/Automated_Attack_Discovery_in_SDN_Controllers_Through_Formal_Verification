import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sdn_project.settings')
django.setup()

from authentication.models import CustomUser
from network_model.models import SDNController, SDNSwitch, SDNHost, CommunicationFlow
from vulnerability_analysis.models import Vulnerability, AttackPath, SecurityAlert
from attack_simulation.models import AttackScenario, SimulationResult
from django.utils import timezone
import random

# ============================================================
# STEP 1: USERS
# ============================================================
print("=" * 50)
print("STEP 1: Creating Users")
print("=" * 50)

if not CustomUser.objects.filter(username='admin').exists():
    admin = CustomUser.objects.create_superuser(
        username='admin', password='Admin@123',
        email='admin@sdn.com', first_name='System',
        last_name='Admin', department='Administration'
    )
    admin.role = 'admin'
    admin.save()
    print(f"  [OK] Admin created: {admin.username}")
else:
    admin = CustomUser.objects.get(username='admin')
    print(f"  [--] Admin already exists: {admin.username}")

if not CustomUser.objects.filter(username='analyst1').exists():
    analyst = CustomUser.objects.create_user(
        username='analyst1', password='Analyst@123',
        email='analyst@sdn.com', first_name='Alice',
        last_name='Johnson', department='Security Operations', role='analyst'
    )
    print(f"  [OK] Analyst created: {analyst.username}")
else:
    analyst = CustomUser.objects.get(username='analyst1')
    print(f"  [--] Analyst already exists: {analyst.username}")

if not CustomUser.objects.filter(username='viewer1').exists():
    viewer = CustomUser.objects.create_user(
        username='viewer1', password='Viewer@123',
        email='viewer@sdn.com', first_name='Bob',
        last_name='Smith', department='IT Department', role='viewer'
    )
    print(f"  [OK] Viewer created: {viewer.username}")
else:
    viewer = CustomUser.objects.get(username='viewer1')
    print(f"  [--] Viewer already exists: {viewer.username}")

print()

# ============================================================
# STEP 2: CONTROLLERS
# ============================================================
print("=" * 50)
print("STEP 2: Creating SDN Controllers")
print("=" * 50)

c1, created = SDNController.objects.get_or_create(
    name='Primary-Controller',
    defaults={
        'ip_address': '192.168.1.1', 'port': 6633,
        'controller_type': 'OpenDaylight', 'version': '1.3',
        'status': 'active',
        'description': 'Main SDN controller managing core switches'
    }
)
print(f"  [{'OK' if created else '--'}] {c1.name} ({c1.ip_address})")

c2, created = SDNController.objects.get_or_create(
    name='Backup-Controller',
    defaults={
        'ip_address': '192.168.1.2', 'port': 6634,
        'controller_type': 'ONOS', 'version': '1.3',
        'status': 'active',
        'description': 'Backup controller for high availability failover'
    }
)
print(f"  [{'OK' if created else '--'}] {c2.name} ({c2.ip_address})")
print(f"  Total Controllers: {SDNController.objects.count()}")
print()

# ============================================================
# STEP 3: SWITCHES
# ============================================================
print("=" * 50)
print("STEP 3: Creating SDN Switches")
print("=" * 50)

switch_data = [
    ('Core-Switch-1',   '00:00:00:00:00:01', '10.0.0.1', '1.3', 'active',      c1, 2000),
    ('Core-Switch-2',   '00:00:00:00:00:02', '10.0.0.2', '1.3', 'active',      c1, 2000),
    ('Edge-Switch-1',   '00:00:00:00:00:03', '10.0.0.3', '1.3', 'active',      c2, 1000),
    ('Edge-Switch-2',   '00:00:00:00:00:04', '10.0.0.4', '1.3', 'compromised', c2, 1000),
    ('Access-Switch-1', '00:00:00:00:00:05', '10.0.0.5', '1.2', 'active',      c1,  500),
]

switches = []
for name, dpid, ip, ofv, status, ctrl, table_size in switch_data:
    sw, created = SDNSwitch.objects.get_or_create(
        name=name,
        defaults={
            'controller': ctrl, 'dpid': dpid, 'ip_address': ip,
            'of_version': ofv, 'status': status,
            'flow_table_size': table_size,
            'description': f'{name} managed by {ctrl.name}'
        }
    )
    switches.append(sw)
    print(f"  [{'OK' if created else '--'}] {sw.name} | {sw.ip_address} | OF {sw.of_version} | {sw.status.upper()}")

print(f"  Total Switches: {SDNSwitch.objects.count()}")
print()

# ============================================================
# STEP 4: HOSTS  (no 'status' field in SDNHost)
# ============================================================
print("=" * 50)
print("STEP 4: Creating SDN Hosts")
print("=" * 50)

host_data = [
    ('Web-Server-1',   '172.16.0.1', 'AA:BB:CC:DD:EE:01', 1, 'Linux Ubuntu 22.04',  False, switches[0]),
    ('DB-Server-1',    '172.16.0.2', 'AA:BB:CC:DD:EE:02', 2, 'Linux CentOS 8',      False, switches[0]),
    ('App-Server-1',   '172.16.0.3', 'AA:BB:CC:DD:EE:03', 1, 'Windows Server 2019', False, switches[1]),
    ('Workstation-1',  '172.16.0.4', 'AA:BB:CC:DD:EE:04', 2, 'Windows 10',          False, switches[1]),
    ('Workstation-2',  '172.16.0.5', 'AA:BB:CC:DD:EE:05', 1, 'Linux Ubuntu 20.04',  False, switches[2]),
    ('IoT-Device-1',   '172.16.0.6', 'AA:BB:CC:DD:EE:06', 3, 'Embedded Linux',      False, switches[2]),
    ('Malicious-Host', '172.16.0.7', 'AA:BB:CC:DD:EE:07', 1, 'Unknown/Kali Linux',  True,  switches[3]),
]

hosts = []
for name, ip, mac, port, os_type, malicious, sw in host_data:
    h, created = SDNHost.objects.get_or_create(
        name=name,
        defaults={
            'switch': sw,
            'ip_address': ip,
            'mac_address': mac,
            'port_number': port,
            'os_type': os_type,
            'is_malicious': malicious,
            'description': f'{name} connected to {sw.name}'
        }
    )
    hosts.append(h)
    flag = " *** MALICIOUS ***" if malicious else ""
    print(f"  [{'OK' if created else '--'}] {h.name} | {h.ip_address}{flag}")

print(f"  Total Hosts: {SDNHost.objects.count()}")
print()

# ============================================================
# STEP 5: COMMUNICATION FLOWS
# ============================================================
print("=" * 50)
print("STEP 5: Creating Communication Flows")
print("=" * 50)

flow_data = [
    (hosts[0], hosts[2], 'TCP',  80,   8080,  False, 15420),
    (hosts[1], hosts[2], 'TCP',  3306, 5432,  False,  8750),
    (hosts[3], hosts[0], 'HTTP', 80,  49201,  False,  3280),
    (hosts[4], hosts[0], 'TCP',  443, 49310,  False,  4190),
    (hosts[5], hosts[1], 'UDP',  161,   161,  False,   920),
    (hosts[6], hosts[0], 'TCP',  80,  49999,  True,  25300),
    (hosts[6], hosts[1], 'TCP',  3306,50000,  True,  18700),
]

for src, dst, proto, sport, dport, suspicious, packets in flow_data:
    flow, created = CommunicationFlow.objects.get_or_create(
        source_host=src,
        dest_host=dst,
        defaults={
            'protocol': proto,
            'src_port': sport,
            'dst_port': dport,
            'is_suspicious': suspicious,
            'packet_count': packets,
        }
    )
    flag = " *** SUSPICIOUS ***" if suspicious else ""
    print(f"  [{'OK' if created else '--'}] {src.ip_address}:{sport} -> {dst.ip_address}:{dport} [{proto}]{flag}")

print(f"  Total Flows: {CommunicationFlow.objects.count()}")
print()

# ============================================================
# STEP 6: VULNERABILITIES
# ============================================================
print("=" * 50)
print("STEP 6: Creating Vulnerabilities")
print("=" * 50)

vuln_data = [
    ('ARP Cache Poisoning Attack',
     'arp_spoofing', 'critical', 9.1, False,
     'SDN Data Plane / Edge Switches',
     'Attacker sends fake ARP replies to poison ARP cache enabling man-in-the-middle attacks.',
     'Implement Dynamic ARP Inspection (DAI) on all switches.'),

    ('Malicious Packet Injection via Compromised Host',
     'packet_injection', 'high', 8.2, False,
     'SDN Data Plane / Flow Processing',
     'Compromised host 172.16.0.7 injects crafted packets to manipulate flow rule installation.',
     'Enable deep packet inspection and whitelist-based packet filtering.'),

    ('OpenFlow Flow Rule Tampering',
     'flow_rule_tampering', 'critical', 9.5, False,
     'SDN Control Plane / Controller',
     'Attacker modifies flow rules without controller authorization redirecting traffic.',
     'Use TLS mutual authentication for all controller-switch OpenFlow channels.'),

    ('LLDP-Based Topology Poisoning',
     'topology_poisoning', 'high', 8.7, False,
     'SDN Topology Discovery / Control Plane',
     'Attacker sends crafted LLDP packets to trick the controller into building incorrect topology.',
     'Authenticate LLDP packets at the controller using cryptographic signatures.'),

    ('OpenFlow Message Replay Attack',
     'replay_attack', 'high', 7.9, False,
     'SDN Control Plane / OpenFlow Protocol',
     'Attacker captures and replays OpenFlow messages to reinstall old malicious flow rules.',
     'Use sequence numbers and timestamps in OpenFlow messages.'),

    ('Man-in-the-Middle on Control Channel',
     'man_in_middle', 'critical', 9.3, True,
     'SDN Control Plane / Controller-Switch Channel',
     'Attacker intercepts communication channel between controller and switches.',
     'Enable TLS 1.3 mutual authentication on all control channels.'),

    ('DoS via Packet-In Message Flood',
     'packet_injection', 'high', 8.0, False,
     'SDN Controller / Control Plane',
     'Attacker floods controller with Packet-In messages exhausting CPU and memory.',
     'Implement Packet-In rate limiting at switch level.'),

    ('Switch Impersonation via Fake DPID',
     'topology_poisoning', 'medium', 6.5, True,
     'SDN Control Plane / Switch Authentication',
     'Attacker connects rogue switch using forged DPID to impersonate legitimate switch.',
     'Implement certificate-based switch authentication.'),
]

vulns = []
for name, vtype, severity, cvss, patched, component, desc, mitigation in vuln_data:
    v, created = Vulnerability.objects.get_or_create(
        name=name,
        defaults={
            'vuln_type': vtype, 'severity': severity,
            'cvss_score': cvss, 'is_patched': patched,
            'affected_component': component,
            'description': desc, 'mitigation': mitigation,
            'detected_at': timezone.now()
        }
    )
    vulns.append(v)
    s = "PATCHED" if patched else "OPEN"
    print(f"  [{'OK' if created else '--'}] {severity.upper():8} | CVSS {cvss} | [{s}] {name}")

print(f"  Total Vulnerabilities: {Vulnerability.objects.count()}")
print()

# ============================================================
# STEP 7: ATTACK PATHS
# ============================================================
print("=" * 50)
print("STEP 7: Creating Attack Paths")
print("=" * 50)

path_data = [
    ('ARP Spoofing to Controller Compromise',
     'critical', 9.2, 75,
     'Malicious-Host (172.16.0.7)', 'SDN Primary Controller',
     ['ARP poisoning on Edge-Switch-2',
      'Intercept controller-switch traffic',
      'Extract OpenFlow session credentials',
      'Inject malicious flow rules via controller',
      'Redirect all network traffic through attacker']),

    ('Topology Poisoning to Traffic Hijacking',
     'high', 8.5, 60,
     'Edge-Switch-2 (Compromised)', 'Web-Server-1 (172.16.0.1)',
     ['Send crafted LLDP packets from compromised switch',
      'Poison controller topology map',
      'Controller installs incorrect forwarding rules',
      'Traffic redirected through attacker path',
      'Full traffic interception achieved']),

    ('Packet Injection to Flow Table Overflow',
     'high', 7.8, 65,
     'Malicious-Host (172.16.0.7)', 'Core-Switch-1 Flow Table',
     ['Craft packets with unique source addresses',
      'Flood switch with unknown destination packets',
      'Controller installs flow rule for each packet',
      'Flow table capacity exhausted',
      'Switch enters fail-open mode']),
]

for name, risk, impact, likelihood, entry, target, steps in path_data:
    path, created = AttackPath.objects.get_or_create(
        name=name,
        defaults={
            'risk_level': risk, 'impact_score': impact,
            'likelihood': likelihood, 'entry_point': entry,
            'target': target, 'steps': steps,
            'description': f'Attack path from {entry} targeting {target}',
            'is_active': True
        }
    )
    if created and len(vulns) >= 2:
        path.vulnerabilities.add(vulns[0], vulns[1])
    print(f"  [{'OK' if created else '--'}] {risk.upper():8} | Impact {impact} | {name}")

print(f"  Total Attack Paths: {AttackPath.objects.count()}")
print()

# ============================================================
# STEP 8: SECURITY ALERTS
# ============================================================
print("=" * 50)
print("STEP 8: Creating Security Alerts")
print("=" * 50)

alert_data = [
    ('Suspicious Traffic from 172.16.0.7',
     'Malicious host sending anomalous TCP packets to internal servers. Possible exploitation.',
     'critical', '172.16.0.7', False),
    ('Unauthorized Flow Rule Modification',
     'Flow rule on Edge-Switch-2 modified without controller instruction. Possible tampering.',
     'high', '10.0.0.4', False),
    ('ARP Storm Detected on Edge Segment',
     'Excessive ARP request rate from 172.16.0.7. Rate exceeds 100/second threshold.',
     'high', '172.16.0.7', False),
    ('Controller Connection Anomaly',
     'Edge-Switch-2 attempted connection to unknown IP 10.0.0.99 not a registered controller.',
     'medium', '10.0.0.4', False),
]

for title, message, severity, source_ip, resolved in alert_data:
    alert, created = SecurityAlert.objects.get_or_create(
        title=title,
        defaults={
            'message': message, 'severity': severity,
            'source_ip': source_ip, 'is_resolved': resolved,
            'created_at': timezone.now()
        }
    )
    s = "RESOLVED" if resolved else "ACTIVE"
    print(f"  [{'OK' if created else '--'}] {severity.upper():8} | [{s}] {title}")

print(f"  Total Alerts: {SecurityAlert.objects.count()}")
print()

# ============================================================
# STEP 9: ATTACK SCENARIOS
# ============================================================
print("=" * 50)
print("STEP 9: Creating Attack Simulation Scenarios")
print("=" * 50)

scenario_data = [
    ('AES-256 DoS Flood Test',
     'dos_flood', 'high',
     'Simulate DoS flood attack targeting the primary controller.',
     'completed', 0.89, 8.5, 9.3),
    ('Flow Table Overflow Simulation',
     'flow_table_overflow', 'high',
     'Test capacity limits of Core-Switch-1 by injecting packets with unique headers.',
     'completed', 0.59, 7.2, 8.4),
    ('Packet Injection via Malicious Host',
     'packet_injection', 'medium',
     'Simulate packet injection from compromised host to test data plane filtering.',
     'pending', 0.0, 0.0, 0.0),
    ('Topology Poisoning Scenario',
     'topology_poisoning', 'high',
     'Test controller resilience against crafted LLDP packets corrupting topology.',
     'pending', 0.0, 0.0, 0.0),
    ('DoS Flood - Controller Stress Test',
     'dos_flood', 'critical',
     'Maximum load stress test targeting both controllers simultaneously.',
     'pending', 0.0, 0.0, 0.0),
    ('ARP Spoofing Detection Test',
     'arp_spoofing', 'medium',
     'Simulate ARP cache poisoning from malicious host to test ARP inspection.',
     'pending', 0.0, 0.0, 0.0),
]

scenarios = []
for name, atype, severity, desc, status, success_rate, feasibility, impact in scenario_data:
    sc, created = AttackScenario.objects.get_or_create(
        name=name,
        defaults={
            'attack_type': atype, 'severity': severity,
            'description': desc, 'status': status,
            'success_rate': success_rate,
            'feasibility_score': feasibility,
            'impact_score': impact,
            'created_by': admin,
            'target_controller': c1,
        }
    )
    scenarios.append(sc)
    print(f"  [{'OK' if created else '--'}] {severity.upper():8} | [{status.upper()}] {name}")

print(f"  Total Scenarios: {AttackScenario.objects.count()}")
print()

# ============================================================
# STEP 10: SIMULATION RESULTS
# ============================================================
print("=" * 50)
print("STEP 10: Creating Simulation Results")
print("=" * 50)

completed = [s for s in scenarios if s.status == 'completed']

result_data = [
    (True, 45200, 3800, 28, ['172.16.0.1', '172.16.0.3'],
     'Attacker floods controller with TCP SYN packets overwhelming the Packet-In queue.',
     [{'time': '0s',  'event': 'Attack initiated — DoS tool started',                'phase': 'setup'},
      {'time': '2s',  'event': 'Network scanned, controller IP identified',          'phase': 'recon'},
      {'time': '5s',  'event': 'Flood packets crafted with spoofed source IPs',      'phase': 'recon'},
      {'time': '8s',  'event': 'Packet flood launched at 45,000 packets/second',     'phase': 'exploit'},
      {'time': '12s', 'event': 'Controller CPU hit 98%, flow installations delayed', 'phase': 'exploit'},
      {'time': '15s', 'event': 'SUCCESS — controller unresponsive for 8 seconds',    'phase': 'impact'}],
     ['Implement Packet-In rate limiting at switch level',
      'Deploy controller load balancing across multiple instances',
      'Enable DDoS protection at network perimeter',
      'Configure switch fail-secure mode instead of fail-open']),

    (True, 18500, 1200, 15, ['10.0.0.1'],
     'Attacker sends packets with unique random source MACs forcing a new flow rule per packet.',
     [{'time': '0s',  'event': 'Attack initiated — packet generator started',  'phase': 'setup'},
      {'time': '2s',  'event': 'Target switch Core-Switch-1 identified',       'phase': 'recon'},
      {'time': '5s',  'event': 'Unique MAC address packets crafted',           'phase': 'recon'},
      {'time': '8s',  'event': 'Packet flood started — flow table filling up', 'phase': 'exploit'},
      {'time': '11s', 'event': 'Flow table at 90% capacity',                   'phase': 'exploit'},
      {'time': '15s', 'event': 'SUCCESS — switch entered fail-open mode',      'phase': 'impact'}],
     ['Set hard limits on flow table entries per host',
      'Enable flow table usage monitoring and alerts',
      'Implement flow aggregation to reduce table entries',
      'Configure controller to reject flows from unknown sources']),
]

for i, sc in enumerate(completed):
    if i < len(result_data):
        r = result_data[i]
        result, created = SimulationResult.objects.get_or_create(
            scenario=sc,
            defaults={
                'is_successful': r[0], 'packets_sent': r[1],
                'packets_dropped': r[2], 'affected_flows': r[3],
                'compromised_nodes': r[4], 'attack_vector': r[5],
                'timeline': r[6], 'recommendations': r[7],
                'raw_output': f'Completed. Success={r[0]}. Sent={r[1]}, Dropped={r[2]}.'
            }
        )
        outcome = "BREACH" if r[0] else "BLOCKED"
        print(f"  [{'OK' if created else '--'}] {sc.name} -> [{outcome}]")

print(f"  Total Results: {SimulationResult.objects.count()}")
print()

# ============================================================
# FINAL SUMMARY
# ============================================================
print("=" * 50)
print("ALL DONE — Data Summary")
print("=" * 50)
print(f"  Users:           {CustomUser.objects.count()}")
print(f"  Controllers:     {SDNController.objects.count()}")
print(f"  Switches:        {SDNSwitch.objects.count()}")
print(f"  Hosts:           {SDNHost.objects.count()}")
print(f"  Flows:           {CommunicationFlow.objects.count()}")
print(f"  Vulnerabilities: {Vulnerability.objects.count()}")
print(f"  Attack Paths:    {AttackPath.objects.count()}")
print(f"  Alerts:          {SecurityAlert.objects.count()}")
print(f"  Sim Scenarios:   {AttackScenario.objects.count()}")
print(f"  Sim Results:     {SimulationResult.objects.count()}")
print()
print("  Login Credentials:")
print("    Admin:   admin    / Admin@123")
print("    Analyst: analyst1 / Analyst@123")
print("    Viewer:  viewer1  / Viewer@123")
print()
print("  Run the server:  python manage.py runserver")
print("  Open browser:    http://127.0.0.1:8000")
print("=" * 50)