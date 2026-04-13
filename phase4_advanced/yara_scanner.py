"""
yara_scanner.py  —  YARA Signature-Based Ransomware Detection
Save at: C:/ransomware_forensic/phase4_advanced/yara_scanner.py

Install:  pip install yara-python
"""

import os, json, math
from datetime import datetime
from collections import Counter
from colorama import Fore, Style, init
init(autoreset=True)

# ── YARA rules written as a Python string (no external .yar file needed) ─────
# Each rule targets a distinct ransomware behavior observable in artifacts.
# The rules deliberately avoid math.entropy() (needs yara-python ≥4.3 + libyara
# built with module support) — we calculate entropy in Python instead and pass
# the flag in.  This makes the scanner portable on any Windows Python install.

RULES_SOURCE = r"""
rule RansomNote_Generic {
    meta:
        id          = "RN-001"
        description = "Detects ransom demand notes by keyword patterns"
        author      = "Ransomware Forensic Framework"
        severity    = "CRITICAL"
        mitre       = "T1486"
    strings:
        $kw1  = "YOUR FILES HAVE BEEN ENCRYPTED"     nocase ascii wide
        $kw2  = "YOUR FILES ARE ENCRYPTED"           nocase ascii wide
        $kw3  = "DECRYPT"                            nocase ascii wide
        $kw4  = "BITCOIN"                            nocase ascii wide
        $kw5  = "BTC"                                nocase ascii wide
        $kw6  = "UNIQUE ID"                          nocase ascii wide
        $kw7  = "CONTACT US"                         nocase ascii wide
        $kw8  = "RESTORE YOUR FILES"                 nocase ascii wide
        $kw9  = "RANSOM"                             nocase ascii wide
        $kw10 = "PAYMENT"                            nocase ascii wide
        $kw11 = "WALLET"                             nocase ascii wide
        $kw12 = "onion"                              nocase ascii wide
    condition:
        3 of ($kw*)
}

rule WannaCry_Markers {
    meta:
        id          = "WC-001"
        description = "Detects WannaCry ransomware artifact markers"
        author      = "Ransomware Forensic Framework"
        severity    = "CRITICAL"
        mitre       = "T1486"
    strings:
        $ext   = ".wncry"            ascii
        $ext2  = ".WNCRY"            ascii
        $magic = "WANACRY!"          ascii
        $note  = "WanaDecryptor"     ascii wide nocase
        $note2 = "@Please_Read_Me@"  ascii
        $note3 = "@WanaDecryptor@"   ascii
    condition:
        any of them
}

rule Locky_Markers {
    meta:
        id          = "LC-001"
        description = "Detects Locky ransomware artifact markers"
        author      = "Ransomware Forensic Framework"
        severity    = "HIGH"
        mitre       = "T1486"
    strings:
        $ext1 = ".locky"   ascii
        $ext2 = ".zepto"   ascii
        $ext3 = ".odin"    ascii
        $ext4 = ".aesir"   ascii
        $note = "_HOWDO_text" ascii nocase
    condition:
        any of them
}

rule Cerber_Markers {
    meta:
        id          = "CB-001"
        description = "Detects Cerber ransomware artifact markers"
        author      = "Ransomware Forensic Framework"
        severity    = "HIGH"
        mitre       = "T1486"
    strings:
        $ext1 = ".cerber"  ascii
        $ext2 = ".cerber2" ascii
        $ext3 = ".cerber3" ascii
        $note = "# DECRYPT MY FILES #" ascii nocase
    condition:
        any of them
}

rule Generic_RansomExtension {
    meta:
        id          = "GR-001"
        description = "Detects files with common ransomware extension patterns in their content"
        author      = "Ransomware Forensic Framework"
        severity    = "MEDIUM"
        mitre       = "T1486"
    strings:
        $e1  = ".locked"     ascii
        $e2  = ".encrypted"  ascii
        $e3  = ".enc"        ascii
        $e4  = ".crypt"      ascii
        $e5  = ".crypto"     ascii
        $e6  = ".vault"      ascii
        $e7  = ".zzz"        ascii
        $e8  = ".pays"       ascii
        $e9  = ".breaking_bad" ascii
        $e10 = ".crypz"      ascii
    condition:
        2 of ($e*)
}

rule ShadowCopy_Deletion {
    meta:
        id          = "SC-001"
        description = "Detects shadow copy deletion commands embedded in files/scripts"
        author      = "Ransomware Forensic Framework"
        severity    = "HIGH"
        mitre       = "T1490"
    strings:
        $cmd1 = "vssadmin delete shadows"         nocase ascii wide
        $cmd2 = "vssadmin.exe Delete Shadows"     nocase ascii wide
        $cmd3 = "wbadmin delete catalog"          nocase ascii wide
        $cmd4 = "bcdedit /set {default}"          nocase ascii wide
        $cmd5 = "wmic shadowcopy delete"          nocase ascii wide
        $cmd6 = "Get-WmiObject Win32_Shadowcopy"  nocase ascii wide
    condition:
        any of them
}

rule Suspicious_Persistence_Script {
    meta:
        id          = "PS-001"
        description = "Detects persistence-related PowerShell/cmd patterns in script files"
        author      = "Ransomware Forensic Framework"
        severity    = "MEDIUM"
        mitre       = "T1547"
    strings:
        $p1 = "CurrentVersion\\Run"              nocase ascii wide
        $p2 = "HKCU\\Software\\Microsoft"        nocase ascii wide
        $p3 = "Set-ItemProperty"                 nocase ascii wide
        $p4 = "New-ItemProperty"                 nocase ascii wide
        $p5 = "reg add"                          nocase ascii wide
        $p6 = "schtasks /create"                 nocase ascii wide
    condition:
        2 of ($p*)
}

rule Phishing_Dropper_Markers {
    meta:
        id          = "PH-001"
        description = "Detects macro/dropper patterns used in phishing initial access"
        author      = "Ransomware Forensic Framework"
        severity    = "HIGH"
        mitre       = "T1566"
    strings:
        $m1 = "AutoOpen"        ascii wide nocase
        $m2 = "Document_Open"  ascii wide nocase
        $m3 = "Shell("         ascii wide nocase
        $m4 = "WScript.Shell"  ascii wide nocase
        $m5 = "CreateObject("  ascii wide nocase
        $m6 = "powershell -enc" ascii wide nocase
        $m7 = "cmd /c start"    ascii wide nocase
    condition:
        2 of ($m*)
}
"""


# ── entropy helper (Python-side, bypasses libyara math module requirement) ──

def _entropy(path: str) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        if not data:
            return 0.0
        freq = Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in freq.values() if c)
    except Exception:
        return 0.0


# ── scanner ──────────────────────────────────────────────────────────────────

def run_yara_scan(scan_path: str = r"C:\ransomware_forensic\artifacts") -> list:
    """
    Scan every file in scan_path against all YARA rules above.
    Falls back to extension + entropy analysis if yara-python is unavailable.
    Returns list of match dicts.
    """
    results = []
    print(f"\n{Fore.CYAN}[*] YARA Signature Scan — {scan_path}{Style.RESET_ALL}")

    # ── try importing yara-python ─────────────────────────────────────────────
    yara_available = False
    rules = None
    try:
        import yara
        rules = yara.compile(source=RULES_SOURCE)
        yara_available = True
        print(f"  {Fore.GREEN}[+] yara-python loaded — full signature scanning active{Style.RESET_ALL}")
    except ImportError:
        print(f"  {Fore.YELLOW}[!] yara-python not installed — running extension+entropy fallback{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}    Install with: pip install yara-python{Style.RESET_ALL}")
    except Exception as e:
        print(f"  {Fore.YELLOW}[!] YARA compile warning: {e} — running fallback{Style.RESET_ALL}")

    if not os.path.isdir(scan_path):
        print(f"  {Fore.RED}[✗] Scan path not found: {scan_path}{Style.RESET_ALL}")
        return results

    RANSOM_EXTENSIONS = {
        ".locked", ".wncry", ".enc", ".crypto", ".crypt",
        ".encrypted", ".cerber", ".cerber2", ".cerber3",
        ".locky", ".zepto", ".odin", ".aesir", ".zzz",
        ".pays", ".crypz", ".vault", ".breaking_bad",
    }
    RANSOM_NOTE_NAMES = {
        "readme_decrypt.txt", "how_to_decrypt.txt",
        "decrypt_instructions.txt", "help_restore_files.txt",
        "@please_read_me@.txt", "@wanadecryptor@.txt",
        "howto_restore_files.txt", "recovery_file.txt",
    }

    print(f"\n  {'File':<40} {'Entropy':>8}  {'YARA Match / Flag'}")
    print(f"  {'─'*40} {'─'*8}  {'─'*30}")

    for fname in sorted(os.listdir(scan_path)):
        fpath = os.path.join(scan_path, fname)
        if not os.path.isfile(fpath):
            continue

        _, ext = os.path.splitext(fname.lower())
        fname_lower = fname.lower()
        file_entropy = round(_entropy(fpath), 4)
        matched_rules = []
        flags = []

        # ── YARA matching ─────────────────────────────────────────────────────
        if yara_available and rules:
            try:
                matches = rules.match(fpath)
                for m in matches:
                    rule_id   = m.meta.get("id", m.rule)
                    severity  = m.meta.get("severity", "MEDIUM")
                    mitre_id  = m.meta.get("mitre", "")
                    matched_rules.append({
                        "rule":     m.rule,
                        "rule_id":  rule_id,
                        "severity": severity,
                        "mitre":    mitre_id,
                        "strings":  [str(s) for s in m.strings][:5],
                    })
            except Exception as e:
                flags.append(f"yara-error:{e}")

        # ── Python-side heuristics (always run, complement YARA) ──────────────
        if ext in RANSOM_EXTENSIONS:
            flags.append("ransomware-extension")
        if fname_lower in RANSOM_NOTE_NAMES:
            flags.append("ransom-note-filename")
        if file_entropy > 7.5:
            flags.append(f"high-entropy:{file_entropy}")
        elif file_entropy > 7.2:
            flags.append(f"elevated-entropy:{file_entropy}")

        # ── only record if anything suspicious ───────────────────────────────
        if matched_rules or flags:
            severity = "CRITICAL" if any(
                r.get("severity") == "CRITICAL" for r in matched_rules
            ) or "ransom-note-filename" in flags or file_entropy > 7.8 else "HIGH"

            entry = {
                "file":          fpath,
                "basename":      fname,
                "entropy":       file_entropy,
                "yara_matches":  matched_rules,
                "heuristic_flags": flags,
                "severity":      severity,
                "timestamp":     datetime.now().isoformat(),
            }
            results.append(entry)

            rule_names = [r["rule"] for r in matched_rules] + flags
            color = Fore.RED if severity == "CRITICAL" else Fore.YELLOW
            print(f"  {color}{fname:<40} {file_entropy:>8.4f}  {', '.join(rule_names)}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.WHITE}{fname:<40} {file_entropy:>8.4f}  {Fore.GREEN}✓ clean{Style.RESET_ALL}")

    print(f"\n  {Fore.YELLOW}[*] {len(results)} file(s) flagged by YARA/heuristics{Style.RESET_ALL}")

    os.makedirs("reports", exist_ok=True)
    with open("reports/yara_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"  {Fore.GREEN}[✓] Results saved → reports/yara_results.json{Style.RESET_ALL}")
    return results


if __name__ == "__main__":
    run_yara_scan(r'C:\Users\Dell\Desktop\ransomware_forensis\artifacts")