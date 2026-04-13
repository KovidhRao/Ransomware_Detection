"""
mitre_mapper.py  —  Full MITRE ATT&CK Mapping Engine
Save at: C:/ransomware_forensic/phase4_advanced/mitre_mapper.py

Covers 15 ransomware-relevant ATT&CK techniques with sub-techniques,
evidence correlation, and confidence scoring.
"""

import json, os, re
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)


# ── MITRE ATT&CK technique definitions ───────────────────────────────────────
# Each entry includes: id, sub_id, name, tactic, description, detection_logic,
# evidence_keys (what JSON fields we look for), and reference URL.

TECHNIQUE_CATALOG = [
    {
        "id":          "T1566",
        "sub_id":      "T1566.001",
        "name":        "Phishing: Spearphishing Attachment",
        "tactic":      "Initial Access",
        "tactic_id":   "TA0001",
        "description": "Adversary sends malicious email attachment (e.g., macro-enabled Office doc) to gain initial foothold on victim system.",
        "evidence_keys": ["office_spawned_cmd", "word_cmd_event", "phishing_marker"],
        "reference":   "https://attack.mitre.org/techniques/T1566/001/",
        "detection":   "office_spawned_child_process",
        "ioc_type":    "process",
    },
    {
        "id":          "T1059",
        "sub_id":      "T1059.001",
        "name":        "Command and Scripting Interpreter: PowerShell",
        "tactic":      "Execution",
        "tactic_id":   "TA0002",
        "description": "Adversary uses PowerShell to download payload, disable defenses, or execute ransomware binary after initial access.",
        "evidence_keys": ["powershell_event", "powershell_process", "ps_suspicious"],
        "reference":   "https://attack.mitre.org/techniques/T1059/001/",
        "detection":   "powershell_spawned_by_office",
        "ioc_type":    "process",
    },
    {
        "id":          "T1059",
        "sub_id":      "T1059.003",
        "name":        "Command and Scripting Interpreter: Windows Command Shell",
        "tactic":      "Execution",
        "tactic_id":   "TA0002",
        "description": "cmd.exe used to execute ransomware commands, disable recovery options, or run secondary payloads.",
        "evidence_keys": ["cmd_spawned", "cmd_event", "word_cmd_event"],
        "reference":   "https://attack.mitre.org/techniques/T1059/003/",
        "detection":   "cmd_process_detected",
        "ioc_type":    "process",
    },
    {
        "id":          "T1547",
        "sub_id":      "T1547.001",
        "name":        "Boot/Logon Autostart: Registry Run Keys / Startup Folder",
        "tactic":      "Persistence",
        "tactic_id":   "TA0003",
        "description": "Ransomware writes executable path into HKCU/HKLM Run keys to survive system reboots and maintain persistence.",
        "evidence_keys": ["suspicious_registry", "registry_run_key", "reg_persistence"],
        "reference":   "https://attack.mitre.org/techniques/T1547/001/",
        "detection":   "registry_run_key_written",
        "ioc_type":    "registry",
    },
    {
        "id":          "T1112",
        "sub_id":      "T1112",
        "name":        "Modify Registry",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Adversary modifies registry to disable Windows Defender, modify security settings, or store configuration data.",
        "evidence_keys": ["registry_modified", "defender_disabled", "security_center_reg"],
        "reference":   "https://attack.mitre.org/techniques/T1112/",
        "detection":   "registry_modification_event",
        "ioc_type":    "registry",
    },
    {
        "id":          "T1562",
        "sub_id":      "T1562.001",
        "name":        "Impair Defenses: Disable or Modify Tools",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Ransomware disables antivirus, Windows Defender, or security monitoring tools to avoid detection during encryption.",
        "evidence_keys": ["defender_disabled", "av_stopped", "security_service_stopped"],
        "reference":   "https://attack.mitre.org/techniques/T1562/001/",
        "detection":   "security_tool_disabled",
        "ioc_type":    "process",
    },
    {
        "id":          "T1082",
        "sub_id":      "T1082",
        "name":        "System Information Discovery",
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "description": "Ransomware enumerates system information (OS version, drives, network shares) to identify encryption targets.",
        "evidence_keys": ["system_enum", "drive_enum", "whoami_event", "systeminfo_event"],
        "reference":   "https://attack.mitre.org/techniques/T1082/",
        "detection":   "system_enumeration_commands",
        "ioc_type":    "process",
    },
    {
        "id":          "T1083",
        "sub_id":      "T1083",
        "name":        "File and Directory Discovery",
        "tactic":      "Discovery",
        "tactic_id":   "TA0007",
        "description": "Ransomware recursively enumerates directories to locate files for encryption, targeting documents, images, and databases.",
        "evidence_keys": ["mass_file_access", "mass_file_ops", "file_enum_event"],
        "reference":   "https://attack.mitre.org/techniques/T1083/",
        "detection":   "mass_file_enumeration",
        "ioc_type":    "file",
    },
    {
        "id":          "T1486",
        "sub_id":      "T1486",
        "name":        "Data Encrypted for Impact",
        "tactic":      "Impact",
        "tactic_id":   "TA0040",
        "description": "Core ransomware behavior: encrypts victim files using AES/RSA to render them inaccessible and demand ransom.",
        "evidence_keys": ["encrypted_files", "high_entropy", "ransom_note", "encrypted_extension"],
        "reference":   "https://attack.mitre.org/techniques/T1486/",
        "detection":   "high_entropy_files_with_ransom_extension",
        "ioc_type":    "file",
    },
    {
        "id":          "T1490",
        "sub_id":      "T1490",
        "name":        "Inhibit System Recovery",
        "tactic":      "Impact",
        "tactic_id":   "TA0040",
        "description": "Ransomware deletes Volume Shadow Copies and disables recovery to prevent victims from restoring files without paying.",
        "evidence_keys": ["vssadmin_detected", "shadow_deletion", "vss_event", "bcdedit_event"],
        "reference":   "https://attack.mitre.org/techniques/T1490/",
        "detection":   "vssadmin_delete_shadows_command",
        "ioc_type":    "process",
    },
    {
        "id":          "T1489",
        "sub_id":      "T1489",
        "name":        "Service Stop",
        "tactic":      "Impact",
        "tactic_id":   "TA0040",
        "description": "Ransomware stops database, backup, and security services before encryption to ensure target files are not locked.",
        "evidence_keys": ["service_stopped", "net_stop_event", "taskkill_event"],
        "reference":   "https://attack.mitre.org/techniques/T1489/",
        "detection":   "service_stop_commands",
        "ioc_type":    "process",
    },
    {
        "id":          "T1485",
        "sub_id":      "T1485",
        "name":        "Data Destruction",
        "tactic":      "Impact",
        "tactic_id":   "TA0040",
        "description": "Some ransomware variants permanently destroy or overwrite original files after encryption, preventing recovery.",
        "evidence_keys": ["file_deleted", "original_file_removed", "sdelete_event"],
        "reference":   "https://attack.mitre.org/techniques/T1485/",
        "detection":   "original_files_deleted_post_encryption",
        "ioc_type":    "file",
    },
    {
        "id":          "T1070",
        "sub_id":      "T1070.004",
        "name":        "Indicator Removal: File Deletion",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Ransomware deletes its own dropper/binary after execution to hinder forensic investigation and detection.",
        "evidence_keys": ["dropper_deleted", "self_delete", "temp_file_removed"],
        "reference":   "https://attack.mitre.org/techniques/T1070/004/",
        "detection":   "executable_self_deletion",
        "ioc_type":    "file",
    },
    {
        "id":          "T1027",
        "sub_id":      "T1027",
        "name":        "Obfuscated Files or Information",
        "tactic":      "Defense Evasion",
        "tactic_id":   "TA0005",
        "description": "Ransomware payload or configuration is encoded/encrypted to evade static antivirus detection.",
        "evidence_keys": ["high_entropy", "encoded_payload", "base64_content"],
        "reference":   "https://attack.mitre.org/techniques/T1027/",
        "detection":   "high_entropy_executable_or_config",
        "ioc_type":    "file",
    },
    {
        "id":          "T1204",
        "sub_id":      "T1204.002",
        "name":        "User Execution: Malicious File",
        "tactic":      "Execution",
        "tactic_id":   "TA0002",
        "description": "Victim opens a malicious file attachment (e.g., Office doc with macro), triggering the ransomware infection chain.",
        "evidence_keys": ["office_spawned_cmd", "word_cmd_event", "user_executed_payload"],
        "reference":   "https://attack.mitre.org/techniques/T1204/002/",
        "detection":   "user_opened_malicious_attachment",
        "ioc_type":    "process",
    },
]


# ── evidence extraction helpers ───────────────────────────────────────────────

def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _build_evidence_flags() -> dict:
    """
    Read every available JSON report and build a flat dict of evidence flags.
    Flag = True when the corresponding artifact is found.
    """
    flags = {}

    # ── file scan ─────────────────────────────────────────────────────────────
    scan = _load("reports/file_scan_results.json") or {}
    flags["encrypted_files"]     = len(scan.get("encrypted_files", [])) > 0
    flags["encrypted_extension"] = flags["encrypted_files"]
    flags["ransom_note"]         = len(scan.get("ransom_notes", [])) > 0

    # ── entropy ───────────────────────────────────────────────────────────────
    ent = _load("reports/entropy_results.json") or []
    high_ent = [r for r in ent if isinstance(r, dict) and r.get("entropy", 0) > 7.2]
    flags["high_entropy"]        = len(high_ent) > 0

    # ── registry ──────────────────────────────────────────────────────────────
    reg = _load("reports/registry_findings.json") or []
    sus_reg = [r for r in reg if isinstance(r, dict) and r.get("suspicious")]
    flags["suspicious_registry"] = len(sus_reg) > 0
    flags["registry_run_key"]    = any(
        "run" in r.get("key", "").lower() for r in sus_reg
    )
    flags["reg_persistence"]     = flags["suspicious_registry"]
    flags["registry_modified"]   = flags["suspicious_registry"]

    # ── event logs ────────────────────────────────────────────────────────────
    events = _load("artifacts/simulated_event_logs.json") or []
    descs  = [e.get("desc", "").lower() for e in events]

    def _any(*keywords):
        return any(all(k in d for k in keywords) for d in descs)

    flags["vssadmin_detected"]   = _any("vssadmin")
    flags["shadow_deletion"]     = _any("vssadmin", "shadow")
    flags["vss_event"]           = flags["vssadmin_detected"]
    flags["bcdedit_event"]       = _any("bcdedit")
    flags["word_cmd_event"]      = _any("word", "cmd")
    flags["office_spawned_cmd"]  = _any("word", "cmd") or _any("excel", "cmd")
    flags["cmd_event"]           = _any("cmd.exe") or _any("ransom")
    flags["cmd_spawned"]         = flags["cmd_event"]
    flags["powershell_event"]    = _any("powershell")
    flags["powershell_process"]  = flags["powershell_event"]
    flags["ps_suspicious"]       = flags["powershell_event"]
    flags["mass_file_access"]    = _any("mass")
    flags["mass_file_ops"]       = _any("mass")
    flags["file_enum_event"]     = _any("file access")
    flags["service_stopped"]     = _any("service")
    flags["net_stop_event"]      = _any("net stop")
    flags["taskkill_event"]      = _any("taskkill")
    flags["user_executed_payload"] = _any("word") or _any("excel")
    flags["phishing_marker"]     = flags["word_cmd_event"]

    # ── process monitor ───────────────────────────────────────────────────────
    procs = _load("reports/process_findings.json") or []
    proc_names = [p.get("name", "").lower() for p in procs]
    flags["file_deleted"]        = any("sdelete" in n for n in proc_names)
    flags["sdelete_event"]       = flags["file_deleted"]
    flags["original_file_removed"] = flags["encrypted_files"]  # originals replaced

    # ── YARA ─────────────────────────────────────────────────────────────────
    yara_res = _load("reports/yara_results.json") or []
    flags["encoded_payload"]     = len(yara_res) > 0
    flags["base64_content"]      = False   # would need deeper analysis

    # ── derived ───────────────────────────────────────────────────────────────
    flags["dropper_deleted"]     = flags.get("file_deleted", False)
    flags["self_delete"]         = flags.get("file_deleted", False)
    flags["temp_file_removed"]   = flags.get("file_deleted", False)
    flags["system_enum"]         = _any("systeminfo") or _any("whoami")
    flags["drive_enum"]          = _any("whoami") or _any("net use")
    flags["whoami_event"]        = _any("whoami")
    flags["systeminfo_event"]    = _any("systeminfo")
    flags["av_stopped"]          = flags.get("service_stopped", False)
    flags["security_service_stopped"] = flags.get("service_stopped", False)
    flags["defender_disabled"]   = False   # would need Defender log
    flags["security_center_reg"] = False

    return flags


def _confidence(technique: dict, flags: dict) -> str:
    """
    Score confidence based on how many evidence keys are present.
    HIGH  = >50% of keys present
    MEDIUM = any key present
    LOW   = no key (technique not triggered)
    """
    keys    = technique["evidence_keys"]
    matched = sum(1 for k in keys if flags.get(k))
    if matched == 0:
        return "NONE"
    if matched / len(keys) >= 0.5:
        return "HIGH"
    return "MEDIUM"


# ── main mapper ───────────────────────────────────────────────────────────────

def run_full_mitre_mapping() -> list:
    print(f"\n{Fore.CYAN}[*] MITRE ATT&CK Full Mapping ({len(TECHNIQUE_CATALOG)} techniques){Style.RESET_ALL}\n")

    flags    = _build_evidence_flags()
    detected = []

    tactic_order = ["TA0001","TA0002","TA0003","TA0005","TA0007","TA0040"]
    catalog_sorted = sorted(
        TECHNIQUE_CATALOG,
        key=lambda t: (tactic_order.index(t["tactic_id"])
                       if t["tactic_id"] in tactic_order else 99)
    )

    current_tactic = None
    for tech in catalog_sorted:
        confidence = _confidence(tech, flags)
        triggered  = confidence in ("HIGH", "MEDIUM")

        if tech["tactic"] != current_tactic:
            current_tactic = tech["tactic"]
            print(f"  {Fore.CYAN}── {current_tactic.upper()} ({tech['tactic_id']}) ──{Style.RESET_ALL}")

        color  = Fore.RED if confidence == "HIGH" else (
                 Fore.YELLOW if confidence == "MEDIUM" else Fore.WHITE)
        symbol = "✅" if triggered else "○"
        conf_label = f"[{confidence}]" if triggered else "[NOT DETECTED]"

        print(f"  {color}{symbol} {tech['sub_id']:<14} {tech['name']:<52} {conf_label}{Style.RESET_ALL}")

        if triggered:
            # Collect which evidence keys fired
            evidence_found = [k for k in tech["evidence_keys"] if flags.get(k)]
            entry = {
                "id":          tech["id"],
                "sub_id":      tech["sub_id"],
                "name":        tech["name"],
                "tactic":      tech["tactic"],
                "tactic_id":   tech["tactic_id"],
                "desc":        tech["description"],
                "confidence":  confidence,
                "detection":   tech["detection"],
                "ioc_type":    tech["ioc_type"],
                "evidence":    evidence_found,
                "reference":   tech["reference"],
                "timestamp":   datetime.now().isoformat(),
            }
            detected.append(entry)

    # Summary by tactic
    tactics_hit = {}
    for t in detected:
        tactics_hit.setdefault(t["tactic"], []).append(t["sub_id"])

    print(f"\n  {Fore.YELLOW}{'─'*70}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Detected {len(detected)}/{len(TECHNIQUE_CATALOG)} techniques across {len(tactics_hit)} tactic(s):{Style.RESET_ALL}")
    for tactic, ids in tactics_hit.items():
        print(f"    {Fore.WHITE}{tactic}: {', '.join(ids)}{Style.RESET_ALL}")

    os.makedirs("reports", exist_ok=True)
    with open("reports/mitre_mapping.json", "w") as f:
        json.dump(detected, f, indent=2)
    print(f"\n  {Fore.GREEN}[✓] MITRE mapping saved → reports/mitre_mapping.json{Style.RESET_ALL}")
    return detected


if __name__ == "__main__":
    run_full_mitre_mapping()