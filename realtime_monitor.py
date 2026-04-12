import os, math, time, json, threading
from collections import Counter
from datetime import datetime
from pathlib import Path
from plyer import notification
from colorama import Fore, init

init(autoreset=True)

# ── CONFIG ──────────────────────────────────────────────────────
WATCH_DIR = r'C:\Users\Dell\Desktop\ransomware_forensi\artifacts'
SCAN_INTERVAL = 10  # seconds between scans
ENTROPY_THRESH = 7.2  # files above this are flagged
ALERT_THRESHOLD = 2  # how many suspicious files trigger alert
LOG_FILE = r'reports\monitor_log.json'
RANSOM_EXTENSIONS = {'.locked', '.wncry', '.enc',
                     '.crypto', '.crypt', '.encrypted'}
RANSOM_NOTES = {'README_DECRYPT.TXT', 'HOW_TO_DECRYPT.TXT',
                'DECRYPT_INSTRUCTIONS.TXT', 'HELP_RESTORE_FILES.TXT'}

alert_history = []  # track what we've already alerted


# ── ENTROPY ─────────────────────────────────────────────────────
def entropy(path):
    try:
        with open(path, 'rb') as f:
            data = f.read(65536)
        if not data: return 0.0
        freq = Counter(data)
        total = len(data)
        # Standard Shannon Entropy Formula
        return -sum((c / total) * math.log2(c / total) for c in freq.values() if c)
    except Exception:
        return 0.0


# ── NOTIFY ──────────────────────────────────────────────────────
def fire_notification(title, message):
    """Fire a Windows desktop toast notification"""
    try:
        notification.notify(
            title=title,
            message=message,
            app_name='Ransomware Forensic Monitor',
            timeout=8
        )
        print(f"  {Fore.MAGENTA}[🔔 NOTIFIED] {title}")
    except Exception as e:
        print(f"  {Fore.RED}[Notification error: {e}]")


# ── SCAN ────────────────────────────────────────────────────────
def scan_once():
    global alert_history
    findings = {
        'time': datetime.now().isoformat(),
        'encrypted': [],
        'ransom_notes': [],
        'high_entropy': [],
        'alerts_fired': []
    }

    if not os.path.exists(WATCH_DIR):
        # Create directory if it doesn't exist to avoid errors
        os.makedirs(WATCH_DIR, exist_ok=True)
        return findings

    for fname in os.listdir(WATCH_DIR):
        fpath = os.path.join(WATCH_DIR, fname)
        if not os.path.isfile(fpath):
            continue

        _, ext = os.path.splitext(fname.lower())
        fname_upper = fname.upper()

        # Check ransom note
        if fname_upper in RANSOM_NOTES:
            findings['ransom_notes'].append(fname)
            key = f'note:{fname}'
            if key not in alert_history:
                alert_history.append(key)
                fire_notification(
                    '🚨 RANSOM NOTE DETECTED',
                    f'File found: {fname}\nLocation: {WATCH_DIR}'
                )
                findings['alerts_fired'].append('ransom_note')

        # Check encrypted extension
        if ext in RANSOM_EXTENSIONS:
            findings['encrypted'].append(fname)

        # Check entropy
        e = entropy(fpath)
        if e > ENTROPY_THRESH:
            findings['high_entropy'].append({'file': fname, 'entropy': round(e, 3)})

    # Fire alert if multiple encrypted files found
    enc_count = len(findings['encrypted'])
    key = f'enc_batch:{enc_count}'
    if enc_count >= ALERT_THRESHOLD and key not in alert_history:
        alert_history.append(key)
        fire_notification(
            f'⚠️ RANSOMWARE ACTIVITY',
            f'{enc_count} Encrypted files detected in {WATCH_DIR}'
        )
        findings['alerts_fired'].append(f'encrypted_batch_{enc_count}')

    # Fire alert for mass high-entropy
    he_count = len(findings['high_entropy'])
    key2 = f'entropy_batch:{he_count}'
    if he_count >= ALERT_THRESHOLD and key2 not in alert_history:
        alert_history.append(key2)
        fire_notification(
            f'🔬 HIGH ENTROPY DETECTED',
            f'{he_count} files show encryption-level randomness.'
        )
        findings['alerts_fired'].append(f'entropy_batch_{he_count}')

    return findings


# ── LOGGING ─────────────────────────────────────────────────────
def log_result(findings):
    os.makedirs('reports', exist_ok=True)
    log = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                log = json.load(f)
        except:
            log = []

    log.append(findings)
    log = log[-500:]  # keep last 500 entries
    with open(LOG_FILE, 'w') as f:
        json.dump(log, f, indent=2)


# ── MAIN LOOP ───────────────────────────────────────────────────
def monitor_loop():
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║   🔔 RANSOMWARE REAL-TIME MONITOR ACTIVE    ║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════╝\n")
    print(f"  Watching: {Fore.YELLOW}{WATCH_DIR}")
    print(f"  Interval: {Fore.YELLOW}{SCAN_INTERVAL}s")
    print(f"  Press {Fore.RED}Ctrl+C{Fore.WHITE} to stop\n")

    scan_count = 0
    while True:
        try:
            scan_count += 1
            ts = datetime.now().strftime("%H:%M:%S")
            findings = scan_once()

            enc = len(findings['encrypted'])
            he = len(findings['high_entropy'])
            rn = len(findings['ransom_notes'])

            status = f"{Fore.RED}🚨 ALERT" if (enc > 0 or rn > 0 or he >= ALERT_THRESHOLD) else f"{Fore.GREEN}✓ CLEAN"
            print(f"  [{ts}] Scan #{scan_count:04d} | Encrypted:{enc} HighEntropy:{he} Notes:{rn} | {status}")

            if findings['alerts_fired']:
                log_result(findings)

            time.sleep(SCAN_INTERVAL)

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Monitor stopped.")
            break


if __name__ == '__main__':
    monitor_loop()