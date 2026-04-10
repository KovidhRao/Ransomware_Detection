import os, json
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

RANSOM_EXTENSIONS = {
    '.locked': 'Generic', '.wncry': 'WannaCry',
    '.enc': 'Generic',    '.crypto': 'CryptoLocker',
    '.crypt': 'Generic',   '.cerber': 'Cerber',
    '.zzz': 'Locky',       '.zepto': 'Locky',
    '.aes256': 'Generic',  '.encrypted': 'Generic',
}

RANSOM_NOTES = ['README_DECRYPT.txt', 'HOW_TO_DECRYPT.txt',
                'DECRYPT_INSTRUCTIONS.txt', 'HELP_RESTORE_FILES.txt']

def scan_directory(scan_path):
    results = {
        'scan_time': datetime.now().isoformat(),
        'scan_path': scan_path,
        'encrypted_files': [],
        'ransom_notes': [],
        'total_files': 0,
        'encrypted_count': 0
    }

    print(f"\n{Fore.CYAN}[*] Scanning: {scan_path}\n")

    for root, dirs, files in os.walk(scan_path):
        for fname in files:
            results['total_files'] += 1
            fpath = os.path.join(root, fname)
            _, ext = os.path.splitext(fname.lower())

            # Check for ransom note
            if fname in RANSOM_NOTES:
                results['ransom_notes'].append(fpath)
                print(f"  {Fore.RED}[!] RANSOM NOTE: {fpath}")

            # Check for encrypted extension
            if ext in RANSOM_EXTENSIONS:
                entry = {
                    'path': fpath,
                    'extension': ext,
                    'family': RANSOM_EXTENSIONS[ext],
                    'size_bytes': os.path.getsize(fpath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat()
                }
                results['encrypted_files'].append(entry)
                results['encrypted_count'] += 1
                print(f"  {Fore.YELLOW}[+] Encrypted: {fname} ({RANSOM_EXTENSIONS[ext]})")

    print(f"\n{Fore.GREEN}[✓] Scan complete: {results['encrypted_count']} encrypted files, {len(results['ransom_notes'])} ransom notes")
    with open('reports/file_scan_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    return results

if __name__ == '__main__':
    os.makedirs('reports', exist_ok=True)
    scan_directory(r'C:\ransomware_forensic\artifacts')