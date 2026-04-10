import winreg, json, os
from colorama import Fore, init
init(autoreset=True)

# Keys where ransomware commonly writes persistence
PERSISTENCE_KEYS = [
    (winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_CURRENT_USER,  r'Software\RansomwareForensicTest\Persistence'),  # our test key
]

SUSPICIOUS_PATTERNS = [
    'temp', 'appdata\\roaming', 'public',
    'programdata', '.exe --silent', '/autostart'
]

def is_suspicious(value_str):
    v = value_str.lower()
    return any(p in v for p in SUSPICIOUS_PATTERNS)

def inspect_registry():
    print(f"\n{Fore.CYAN}[*] Registry Persistence Inspection")
    findings = []

    for hive, key_path in PERSISTENCE_KEYS:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        try:
            key = winreg.OpenKey(hive, key_path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    suspicious = is_suspicious(str(value))
                    color = Fore.RED if suspicious else Fore.WHITE
                    flag = " ⚠ SUSPICIOUS" if suspicious else ""
                    print(f"  {color}{hive_name}\\...\\{name}{flag}")
                    print(f"    Value: {value}")
                    findings.append({
                        'hive': hive_name, 'key': key_path,
                        'name': name, 'value': str(value),
                        'suspicious': suspicious
                    })
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except FileNotFoundError:
            pass

    suspicious_count = sum(1 for f in findings if f['suspicious'])
    print(f"\n{Fore.YELLOW}[*] {suspicious_count} suspicious registry entries found")
    with open('reports/registry_findings.json', 'w') as f:
        json.dump(findings, f, indent=2)
    return findings

if __name__ == '__main__':
    inspect_registry()