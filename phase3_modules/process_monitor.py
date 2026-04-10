import psutil, json, os
from datetime import datetime
from colorama import Fore, init
init(autoreset=True)

SUSPICIOUS_NAMES = [
    'vssadmin.exe', 'wbadmin.exe', 'bcdedit.exe',
    'cipher.exe', 'sdelete.exe', 'wmic.exe'
]

SUSPICIOUS_PATHS = ['\\temp\\', '\\appdata\\roaming\\', '\\public\\']

SUSPICIOUS_PARENTS = {
    'cmd.exe':        ['winword.exe', 'excel.exe', 'acrord32.exe'],
    'powershell.exe': ['winword.exe', 'excel.exe', 'mshta.exe'],
    'wscript.exe':    ['winword.exe', 'outlook.exe'],
}

def scan_processes():
    print(f"\n{Fore.CYAN}[*] Process Analysis — {datetime.now().isoformat()}")
    findings = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'username', 'cmdline']):
        try:
            info = proc.info
            name_lower = (info['name'] or '').lower()
            exe_lower  = (info['exe']  or '').lower()
            flags = []

            if name_lower in SUSPICIOUS_NAMES:
                flags.append('suspicious-name')
            if any(p in exe_lower for p in SUSPICIOUS_PATHS):
                flags.append('suspicious-path')

            # Check parent-child relationship
            try:
                parent = psutil.Process(info['ppid'])
                parent_name = parent.name().lower()
                if name_lower in SUSPICIOUS_PARENTS:
                    if parent_name in SUSPICIOUS_PARENTS[name_lower]:
                        flags.append(f'bad-parent:{parent_name}')
            except: pass

            if flags:
                print(f"  {Fore.RED}[!] PID {info['pid']:>5} | {info['name']:<22} | Flags: {', '.join(flags)}")
                print(f"      Path: {info['exe']}")
                findings.append({
                    'pid': info['pid'], 'name': info['name'],
                    'exe': info['exe'], 'flags': flags,
                    'cmdline': ' '.join(info['cmdline'] or []),
                    'time': datetime.now().isoformat()
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied): pass

    print(f"\n{Fore.YELLOW}[*] {len(findings)} suspicious processes found")
    with open('reports/process_findings.json', 'w') as f:
        json.dump(findings, f, indent=2)
    return findings

if __name__ == '__main__':
    scan_processes()