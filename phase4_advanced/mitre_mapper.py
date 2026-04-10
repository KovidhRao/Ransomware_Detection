import json
from colorama import Fore, init
init(autoreset=True)

# MITRE ATT&CK Techniques relevant to ransomware
MITRE_TECHNIQUES = {
    'T1486': {
        'name': 'Data Encrypted for Impact',
        'tactic': 'Impact',
        'desc': 'Adversary encrypts data to interrupt availability',
        'indicators': ['encrypted_files', 'high_entropy']
    },
    'T1490': {
        'name': 'Inhibit System Recovery',
        'tactic': 'Impact',
        'desc': 'vssadmin / bcdedit used to delete backups',
        'indicators': ['vssadmin_detected', 'shadow_copy_deletion']
    },
    'T1547': {
        'name': 'Boot/Logon Autostart Execution',
        'tactic': 'Persistence',
        'desc': 'Malicious entries in Run registry keys',
        'indicators': ['suspicious_registry']
    },
    'T1059': {
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
        'desc': 'cmd.exe or PowerShell spawned by Office process',
        'indicators': ['suspicious_process', 'bad_parent_process']
    },
    'T1566': {
        'name': 'Phishing',
        'tactic': 'Initial Access',
        'desc': 'Malicious email attachment as initial vector',
        'indicators': ['office_spawned_cmd']
    },
    'T1489': {
        'name': 'Service Stop',
        'tactic': 'Impact',
        'desc': 'Stopping backup or security services',
        'indicators': ['service_stopped']
    },
}

def map_findings_to_mitre(all_findings: dict) -> list:
    """
    all_findings: combined dict with keys like 'encrypted_files',
    'suspicious_registry', 'vssadmin_detected', etc.
    """
    mapped = []
    print(f"\n{Fore.CYAN}[*] MITRE ATT&CK Mapping\n")
    print(f"{'Technique ID':<12} {'Name':<40} {'Tactic':<20} Status")
    print("-" * 90)

    for tech_id, tech in MITRE_TECHNIQUES.items():
        # Check if any indicator for this technique was found
        triggered = any(all_findings.get(ind, False) for ind in tech['indicators'])
        color = Fore.RED if triggered else Fore.WHITE
        status = "✅ DETECTED" if triggered else "— not observed"
        print(f"  {color}{tech_id:<12} {tech['name']:<40} {tech['tactic']:<20} {status}")
        if triggered:
            mapped.append({'id': tech_id, **tech, 'detected': True})

    print(f"\n{Fore.YELLOW}[*] {len(mapped)} MITRE techniques detected")
    with open('reports/mitre_mapping.json', 'w') as f:
        json.dump(mapped, f, indent=2)
    return mapped

if __name__ == '__main__':
    # Example: pass in findings from previous phases
    example_findings = {
        'encrypted_files': True,
        'high_entropy': True,
        'vssadmin_detected': True,
        'shadow_copy_deletion': True,
        'suspicious_registry': True,
        'suspicious_process': False,
    }
    map_findings_to_mitre(example_findings)