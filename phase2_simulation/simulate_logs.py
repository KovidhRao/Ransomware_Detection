import json, random
from datetime import datetime, timedelta

def generate_event_logs():
    """Simulate Windows Event Log entries for forensic analysis"""
    base_time = datetime.now() - timedelta(hours=3)

    events = [
        # Normal activity before attack
        {'time': (base_time).isoformat(), 'event_id': 4624, 'desc': 'Successful Logon', 'user': 'victim_user', 'suspicious': False},
        {'time': (base_time + timedelta(minutes=5)).isoformat(), 'event_id': 4688, 'desc': 'Process Created: notepad.exe', 'user': 'victim_user', 'suspicious': False},
        # Phishing email opened → malicious attachment
        {'time': (base_time + timedelta(minutes=12)).isoformat(), 'event_id': 4688, 'desc': 'Process Created: WINWORD.EXE spawned cmd.exe', 'user': 'victim_user', 'suspicious': True},
        # Malicious process executes
        {'time': (base_time + timedelta(minutes=13)).isoformat(), 'event_id': 4688, 'desc': 'Process Created: ransom_payload.exe', 'user': 'victim_user', 'suspicious': True},
        # Shadow copy deletion
        {'time': (base_time + timedelta(minutes=14)).isoformat(), 'event_id': 4688, 'desc': 'Process Created: vssadmin.exe delete shadows /all /quiet', 'user': 'SYSTEM', 'suspicious': True},
        # Persistence written
        {'time': (base_time + timedelta(minutes=15)).isoformat(), 'event_id': 4657, 'desc': 'Registry value modified: HKCU\\Run\\WindowsUpdate', 'user': 'victim_user', 'suspicious': True},
        # Mass file operations begin
        {'time': (base_time + timedelta(minutes=16)).isoformat(), 'event_id': 4663, 'desc': 'File access: C:\\Users\\victim_user\\Documents (mass read)', 'user': 'victim_user', 'suspicious': True},
        # Encryption complete, ransom note dropped
        {'time': (base_time + timedelta(minutes=22)).isoformat(), 'event_id': 4663, 'desc': 'File created: README_DECRYPT.txt in multiple directories', 'user': 'victim_user', 'suspicious': True},
    ]

    with open(r'C:\Users\Dell\Desktop\ransomware_forensi\artifacts/simulated_event_logs.json', 'w') as f:
        json.dump(events, f, indent=2)
    print(f"[✓] Generated {len(events)} simulated event log entries")
    return events

if __name__ == '__main__':
    generate_event_logs()