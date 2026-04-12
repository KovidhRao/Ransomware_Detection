import yara, os, json

# Custom YARA rules for ransomware artifact detection
RULES_SOURCE = """
rule RansomNote {
    meta:
        description = "Detects ransomware ransom notes"
        author      = "Your Name"
    strings:
        $a = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $b = "YOUR UNIQUE ID" nocase
        $c = "BTC" nocase
        $d = "bitcoin" nocase
        $e = "decrypt" nocase
    condition:
        2 of them
}

rule SuspiciousExtension {
    meta:
        description = "Detects common ransomware file extensions in content"
    strings:
        $a = ".locked" ascii
        $b = ".wncry"  ascii
        $c = ".cerber" ascii
        $d = ".crypto" ascii
        $e = ".crypt"  ascii
    condition:
        any of them
}

rule HighEntropyMarker {
    meta:
        description = "Files starting with random-looking byte sequences"
    condition:
        filesize > 512 and
        math.entropy(0, filesize) > 7.2
}
"""

def run_yara_scan(scan_path=r'C:\ransomware_forensic\artifacts'):
    # math.entropy requires external module; use simplified version
    rules_simple = RULES_SOURCE.replace(
        'condition:\n        filesize > 512 and\n        math.entropy(0, filesize) > 7.2',
        'condition:\n        filesize > 512'
    )
    rules = yara.compile(source=rules_simple)
    results = []
    print("\n[*] YARA Signature Scan")

    for fname in os.listdir(scan_path):
        fpath = os.path.join(scan_path, fname)
        if not os.path.isfile(fpath): continue
        try:
            matches = rules.match(fpath)
            if matches:
                entry = {'file': fname, 'matched_rules': [m.rule for m in matches]}
                results.append(entry)
                print(f"  ⚠ YARA MATCH: {fname} → {[m.rule for m in matches]}")
        except: pass

    print(f"\n[✓] YARA: {len(results)} files matched rules")
    with open('reports/yara_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    return results

if __name__ == '__main__':
    run_yara_scan()