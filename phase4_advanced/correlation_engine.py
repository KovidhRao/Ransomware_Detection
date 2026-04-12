import json
from colorama import Fore, init
init(autoreset=True)

ALERT_THRESHOLD = 60   # out of 100

INDICATOR_WEIGHTS = {
    'encrypted_files_found':     25,
    'high_entropy_files':         20,
    'ransom_note_found':          20,
    'vssadmin_shadow_delete':     15,
    'suspicious_registry_key':    10,
    'suspicious_process':          8,
    'office_spawned_shell':        7,
    'mass_file_operations':        5,
}

def run_correlation():
    print(f"\n{Fore.CYAN}[*] Multi-Indicator Correlation Engine\n")
    total_score = 0
    triggered = []

    # Load findings from all phases
    findings = {}
    for fname, key in [
        ('reports/file_scan_results.json',  'file_scan'),
        ('reports/entropy_results.json',     'entropy'),
        ('reports/registry_findings.json',   'registry'),
        ('reports/process_findings.json',    'processes'),
        ('artifacts/simulated_event_logs.json', 'events'),
    ]:
        try:
            with open(fname) as f: findings[key] = json.load(f)
        except: findings[key] = []

    # Evaluate each indicator
    checks = {
        'encrypted_files_found':  bool(findings.get('file_scan', {}).get('encrypted_files')),
        'high_entropy_files':      any(r.get('suspicious') for r in findings.get('entropy', [])),
        'ransom_note_found':       bool(findings.get('file_scan', {}).get('ransom_notes')),
        'vssadmin_shadow_delete':  any('vssadmin' in e.get('desc','').lower() for e in findings.get('events', [])),
        'suspicious_registry_key': any(r.get('suspicious') for r in findings.get('registry', [])),
        'suspicious_process':      bool(findings.get('processes')),
        'office_spawned_shell':    any('word' in e.get('desc','').lower() and 'cmd' in e.get('desc','').lower() for e in findings.get('events', [])),
        'mass_file_operations':    any('mass' in e.get('desc','').lower() for e in findings.get('events', [])),
    }

    print(f"{'Indicator':<35} {'Weight':>6}  {'Status'}")
    print("-" * 65)
    for indicator, detected in checks.items():
        weight = INDICATOR_WEIGHTS[indicator]
        color = Fore.RED if detected else Fore.WHITE
        flag  = f"[+{weight}]  ✅ TRIGGERED" if detected else "[  0]  — not detected"
        print(f"  {color}{indicator:<35} {flag}")
        if detected:
            total_score += weight
            triggered.append(indicator)

    print(f"\n{'─'*65}")
    bar = '█' * (total_score // 5)
    color = Fore.RED if total_score >= ALERT_THRESHOLD else Fore.YELLOW
    print(f"  {color}RISK SCORE: {total_score}/100  {bar}")
    if total_score >= ALERT_THRESHOLD:
        print(f"  {Fore.RED}🚨 ALERT: RANSOMWARE ACTIVITY CONFIRMED (score={total_score})")
    else:
        print(f"  {Fore.YELLOW}⚠  Score below threshold. Continue monitoring.")

    result = {'score': total_score, 'triggered': triggered,
              'alert': total_score >= ALERT_THRESHOLD}
    with open(r'C:\Users\Dell\Desktop\ransomware_forensi\reports/correlation_result.json', 'w') as f:
        json.dump(result, f, indent=2)
    return result

if __name__ == '__main__':
    run_correlation()