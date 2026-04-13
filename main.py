"""
main.py  —  Ransomware Forensic Investigation Framework
Save at: C:/ransomware_forensic/main.py

Run:  python main.py
      python main.py --skip-sim     (skip simulation, re-analyse existing artifacts)
      python main.py --report-only  (re-generate report from existing JSON results)
"""

import os, sys, json, time, argparse
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ── project root = wherever main.py lives ────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)

for d in ("artifacts", "baseline", "reports", "logs"):
    os.makedirs(d, exist_ok=True)

# ── banner ────────────────────────────────────────────────────────────────────
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     RANSOMWARE FORENSIC INVESTIGATION FRAMEWORK  v2.0        ║
║     Post-Incident Analysis  |  Open-Source  |  Academic      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

def section(title, color=Fore.YELLOW):
    bar = "─" * 60
    print(f"\n{color}{bar}")
    print(f"  {title}")
    print(f"{bar}{Style.RESET_ALL}")

def ok(msg):   print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {msg}")
def warn(msg): print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):  print(f"  {Fore.RED}[✗]{Style.RESET_ALL} {msg}")
def info(msg): print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} {msg}")


# ── phase runners ─────────────────────────────────────────────────────────────

# def run_phase2_simulation():
#     section("PHASE 2 — Artifact Simulation (Crime Scene Creation)", Fore.MAGENTA)
#     info("Creating simulated ransomware artifacts in artifacts/ ...")
#
#     try:
#         from phase2_simulation.simulate_artifacts import (
#             create_fake_files, simulate_encryption, drop_ransom_notes
#         )
#         files = create_fake_files()
#         simulate_encryption(files)
#         drop_ransom_notes()
#         ok("Encrypted files and ransom note created")
#     except Exception as e:
#         err(f"simulate_artifacts: {e}")
#
#     try:
#         from phase2_simulation.simulate_registry import write_fake_registry_entries
#         write_fake_registry_entries()
#         ok("Registry persistence keys written")
#     except Exception as e:
#         err(f"simulate_registry: {e}")
#
#     try:
#         from phase2_simulation.simulate_logs import generate_event_logs
#         generate_event_logs()
#         ok("Simulated event logs generated")
#     except Exception as e:
#         err(f"simulate_logs: {e}")


def run_phase3_modules():
    section("PHASE 3 — Core Forensic Modules", Fore.CYAN)

    try:
        from phase3_modules.file_scanner import scan_directory
        r = scan_directory("artifacts")
        ok(f"File scan: {r['encrypted_count']} encrypted, {len(r['ransom_notes'])} ransom notes")
    except Exception as e:
        err(f"file_scanner: {e}")

    try:
        from phase3_modules.entropy_analyzer import analyze_directory
        r = analyze_directory("artifacts")
        sus = sum(1 for x in r if x.get("suspicious"))
        ok(f"Entropy analysis: {sus}/{len(r)} files flagged (threshold 7.2)")
    except Exception as e:
        err(f"entropy_analyzer: {e}")

    try:
        from phase3_modules.registry_inspector import inspect_registry
        r = inspect_registry()
        sus = sum(1 for x in r if x.get("suspicious"))
        ok(f"Registry inspection: {sus} suspicious persistence entries")
    except Exception as e:
        err(f"registry_inspector: {e}")

    try:
        from phase3_modules.process_monitor import scan_processes
        r = scan_processes()
        ok(f"Process monitor: {len(r)} suspicious processes flagged")
    except Exception as e:
        err(f"process_monitor: {e}")

    try:
        from phase3_modules.shadow_copy_detector import detect_shadow_deletion
        r = detect_shadow_deletion()
        ok(f"Shadow copy detector: {'VSS deletion detected' if r else 'No VSS deletion'}")
    except Exception as e:
        warn(f"shadow_copy_detector skipped: {e}")


def run_phase4_advanced():
    section("PHASE 4 — Advanced Analysis", Fore.YELLOW)

    try:
        from phase4_advanced.yara_scanner import run_yara_scan
        r = run_yara_scan("artifacts")
        ok(f"YARA scan: {len(r)} file(s) matched ransomware signatures")
    except Exception as e:
        err(f"yara_scanner: {e}")

    try:
        from phase4_advanced.hash_verifier import verify_integrity
        r = verify_integrity()
        ok(f"Hash integrity: {r.get('modified', 0)} file(s) changed from baseline")
    except Exception as e:
        warn(f"hash_verifier skipped (run baseline capture first): {e}")

    try:
        from phase4_advanced.mitre_mapper import run_full_mitre_mapping
        r = run_full_mitre_mapping()
        ok(f"MITRE ATT&CK: {len(r)} technique(s) detected across {len(set(t['tactic'] for t in r))} tactics")
    except Exception as e:
        err(f"mitre_mapper: {e}")

    try:
        from phase4_advanced.correlation_engine import run_correlation
        r = run_correlation()
        color = Fore.RED if r["alert"] else Fore.YELLOW
        print(f"  {color}[SCORE] {r['score']}/100 — {'🚨 RANSOMWARE CONFIRMED' if r['alert'] else 'Below alert threshold'}{Style.RESET_ALL}")
    except Exception as e:
        err(f"correlation_engine: {e}")


def run_phase5_timeline():
    section("PHASE 5 — Attack Timeline Reconstruction", Fore.BLUE)
    try:
        from phase5_timeline.timeline_builder import build_timeline
        r = build_timeline()
        ok(f"Timeline: {len(r)} events reconstructed and sorted")
    except Exception as e:
        err(f"timeline_builder: {e}")


def run_phase6_report():
    section("PHASE 6 — Forensic Report & Dashboard", Fore.GREEN)

    # ── HTML Report ────────────────────────────────────────────────────────────
    out = None
    try:
        from phase6_reports.enhanced_report_generator import generate_enhanced_report
        out = generate_enhanced_report()
        ok(f"Full HTML report saved → {out}")
    except Exception as e:
        err(f"report_generator failed: {e}")
        import traceback
        traceback.print_exc()

    # ── Auto-open report in browser (Windows) ─────────────────────────────────
    if out and os.path.exists(out):
        try:
            import subprocess
            abs_out = os.path.abspath(out)
            subprocess.Popen(["start", "", abs_out], shell=True)
            ok(f"Report opened in browser")
        except Exception:
            info(f"Open manually: {os.path.abspath(out)}")

    # ── Dashboard instructions ─────────────────────────────────────────────────
    print()
    info("To launch the web dashboard, open a NEW CMD window and run:")
    print(f"  {Fore.CYAN}  cd {ROOT}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}  python phase6_reports/dashboard_app.py{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}  Then open: http://127.0.0.1:5000{Style.RESET_ALL}")


# ── summary ───────────────────────────────────────────────────────────────────

def print_summary():
    section("PIPELINE COMPLETE — Summary", Fore.GREEN)
    report_dir = "reports"
    files = [f for f in os.listdir(report_dir) if f.endswith(".json")]

    corr = {}
    try:
        with open(os.path.join(report_dir, "correlation_result.json")) as f:
            corr = json.load(f)
    except Exception:
        pass

    score = corr.get("score", "?")
    alert = corr.get("alert", False)

    print(f"""
  {Fore.WHITE}┌─────────────────────────────────────────────┐
  │  Risk Score  : {Fore.RED if alert else Fore.YELLOW}{score}/100{Fore.WHITE}                          │
  │  Alert       : {Fore.RED + "🚨 YES — RANSOMWARE DETECTED" if alert else Fore.GREEN + "✓ Below threshold"}{Fore.WHITE}
  │  JSON reports: {len(files)} files in reports/           │
  │  Next step   : open the .html report in browser │
  └─────────────────────────────────────────────┘{Style.RESET_ALL}
""")


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Ransomware Forensic Framework")
    parser.add_argument("--skip-sim",    action="store_true",
                        help="Skip simulation, re-analyse existing artifacts")
    parser.add_argument("--report-only", action="store_true",
                        help="Re-generate report from existing JSON results only")
    args = parser.parse_args()

    print(BANNER)
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Root    : {ROOT}")

    t0 = time.time()

    if args.report_only:
        run_phase6_report()
    elif args.skip_sim:
        run_phase3_modules()
        run_phase4_advanced()
        run_phase5_timeline()
        run_phase6_report()
    else:
        # run_phase2_simulation()
        run_phase3_modules()
        run_phase4_advanced()
        run_phase5_timeline()
        run_phase6_report()

    elapsed = round(time.time() - t0, 1)
    print_summary()
    print(f"  {Fore.CYAN}Total time: {elapsed}s{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()