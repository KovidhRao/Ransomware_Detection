import os
from colorama import Fore, init
init(autoreset=True)

from phase2_simulation.simulate_artifacts  import simulate_encryption, create_fake_files, drop_ransom_notes
from phase2_simulation.simulate_registry   import write_fake_registry_entries
from phase2_simulation.simulate_logs       import generate_event_logs
from phase3_modules.file_scanner           import scan_directory
from phase3_modules.entropy_analyzer       import analyze_directory
from phase3_modules.registry_inspector     import inspect_registry
from phase3_modules.process_monitor        import scan_processes
from phase4_advanced.correlation_engine    import run_correlation
from phase4_advanced.mitre_mapper          import map_findings_to_mitre
from phase5_timeline.timeline_builder      import build_timeline
from phase6_reports.report_generator       import generate_report

def banner():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════╗
║    RANSOMWARE FORENSIC INVESTIGATION FRAMEWORK   ║
║    Post-Incident Analysis  |  v1.0               ║
╚══════════════════════════════════════════════════╝""")

def main():
    banner()
    os.makedirs('artifacts', exist_ok=True)
    os.makedirs('reports',   exist_ok=True)
    os.makedirs('baseline',  exist_ok=True)

    print(f"\n{Fore.YELLOW}[PHASE 2] Simulating artifacts...")
    files = create_fake_files()
    simulate_encryption(files)
    drop_ransom_notes()
    write_fake_registry_entries()
    generate_event_logs()

    print(f"\n{Fore.YELLOW}[PHASE 3] Running forensic modules...")
    scan_directory('artifacts')
    analyze_directory('artifacts')
    inspect_registry()
    scan_processes()

    print(f"\n{Fore.YELLOW}[PHASE 4] Running advanced analysis...")
    corr = run_correlation()
    all_findings = {
        'encrypted_files': True, 'high_entropy': True,
        'vssadmin_detected': True, 'shadow_copy_deletion': True,
        'suspicious_registry': True
    }
    map_findings_to_mitre(all_findings)

    print(f"\n{Fore.YELLOW}[PHASE 5] Reconstructing attack timeline...")
    build_timeline()

    print(f"\n{Fore.YELLOW}[PHASE 6] Generating forensic report...")
    report = generate_report()
    print(f"\n{Fore.GREEN}✅ All phases complete! Report: {report}")

if __name__ == '__main__':
    main()