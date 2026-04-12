import os, math, json
from collections import Counter
from colorama import Fore, init
init(autoreset=True)

ENTROPY_THRESHOLD = 7.2   # above this = likely encrypted
CHUNK_SIZE = 65536         # 64KB sample per file

def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    entropy = -sum((c/total) * math.log2(c/total) for c in freq.values() if c > 0)
    return round(entropy, 4)

def entropy_bar(val):
    bars = int((val / 8.0) * 20)
    color = Fore.RED if val > ENTROPY_THRESHOLD else Fore.GREEN
    return f"{color}{'█' * bars}{'░' * (20 - bars)}"

def analyze_directory(path):
    print(f"\n{Fore.CYAN}[*] Entropy Analysis — {path}")
    print(f"{'File':<35} {'Entropy':>8}  {'Visual':>22}  {'Status'}")
    print("-" * 80)

    results = []
    for root, _, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'rb') as f:
                    chunk = f.read(CHUNK_SIZE)
                entropy = calc_entropy(chunk)
                suspicious = entropy > ENTROPY_THRESHOLD
                status = f"{Fore.RED}⚠ ENCRYPTED" if suspicious else f"{Fore.GREEN}✓ NORMAL"
                print(f"  {fname:<33} {entropy:>8.4f}  {entropy_bar(entropy)}  {status}")
                results.append({
                    'file': fpath, 'entropy': entropy,
                    'suspicious': suspicious, 'size': len(chunk)
                })
            except PermissionError:
                pass

    suspicious_count = sum(1 for r in results if r['suspicious'])
    print(f"\n{Fore.YELLOW}[*] {suspicious_count}/{len(results)} files flagged as potentially encrypted")

    with open('reports/entropy_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    return results

if __name__ == '__main__':
    analyze_directory(r'C:\Users\Dell\Desktop\ransomware_forensi\artifacts')