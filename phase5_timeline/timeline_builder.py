import json, os
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

PHASE_COLORS = {
    'Initial Access':  Fore.YELLOW,
    'Execution':       Fore.YELLOW,
    'Persistence':    Fore.MAGENTA,
    'Impact':          Fore.RED,
    'Discovery':      Fore.CYAN,
}

def load_all_artifacts() -> list:
    events = []

    # Load event logs
    try:
        with open('artifacts/simulated_event_logs.json') as f:
            for e in json.load(f):
                events.append({
                    'time': e['time'], 'source': 'Windows Event Log',
                    'description': e['desc'],
                    'event_id': e.get('event_id'),
                    'suspicious': e.get('suspicious', False),
                    'phase': classify_event(e['desc'])
                })
    except: pass

    # Load file scan results
    try:
        with open('reports/file_scan_results.json') as f:
            data = json.load(f)
            for ef in data.get('encrypted_files', []):
                events.append({
                    'time': ef['modified'], 'source': 'File System',
                    'description': f"File encrypted: {os.path.basename(ef['path'])} ({ef['family']})",
                    'suspicious': True, 'phase': 'Impact'
                })
    except: pass

    # Load registry findings
    try:
        with open('artifacts/registry_artifacts.json') as f:
            for reg in json.load(f):
                events.append({
                    'time': reg.get('timestamp', datetime.now().isoformat()),
                    'source': 'Registry',
                    'description': f"Persistence key written: {reg['name']} → {reg['value'][:60]}...",
                    'suspicious': True, 'phase': 'Persistence'
                })
    except: pass

    return sorted(events, key=lambda e: e['time'])

def classify_event(desc: str) -> str:
    d = desc.lower()
    if 'logon' in d: return 'Initial Access'
    if 'process created' in d: return 'Execution'
    if 'registry' in d: return 'Persistence'
    if 'vssadmin' in d or 'decrypt' in d: return 'Impact'
    if 'file access' in d: return 'Discovery'
    return 'Unknown'

def build_timeline():
    events = load_all_artifacts()
    print(f"\n{Fore.CYAN}{'═'*70}")
    print(f"{Fore.CYAN}  ATTACK TIMELINE — {len(events)} events reconstructed")
    print(f"{Fore.CYAN}{'═'*70}\n")

    for i, ev in enumerate(events):
        ts = ev['time'][:19].replace('T', ' ')
        phase = ev.get('phase', 'Unknown')
        color = PHASE_COLORS.get(phase, Fore.WHITE)
        flag = f" {Fore.RED}[⚠ SUSPICIOUS]" if ev['suspicious'] else ""
        connector = "│" if i < len(events) - 1 else "└"
        print(f"  {color}◆ [{ts}] [{phase:<16}] {ev['description']}{flag}")
        print(f"  {Fore.WHITE+connector}  Source: {ev['source']}\n")

    with open('reports/attack_timeline.json', 'w') as f:
        json.dump(events, f, indent=2)
    print(f"{Fore.GREEN}[✓] Timeline saved to reports/attack_timeline.json")
    return events

if __name__ == '__main__':
    build_timeline()