import winreg, json, os
from datetime import datetime

# Safe test key — NOT the real Run key
TEST_KEY_PATH = r'Software\RansomwareForensicTest\Persistence'

FAKE_ENTRIES = [
    ('WindowsUpdate', r'C:\Windows\Temp\svchost32.exe --silent'),
    ('AdobeSync',    r'C:\Users\Public\adobe_helper.exe'),
    ('MicrosoftEdge', r'C:\ProgramData\edge_update.exe /autostart'),
]

def write_fake_registry_entries():
    artifacts = []
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, TEST_KEY_PATH)
    for name, value in FAKE_ENTRIES:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        artifacts.append({
            'key': f'HKCU\\{TEST_KEY_PATH}',
            'name': name,
            'value': value,
            'timestamp': datetime.now().isoformat(),
            'suspicious': True
        })
        print(f"  [+] Registry entry written: {name} -> {value}")
    winreg.CloseKey(key)

    # Save artifacts log
    with open('artifacts/registry_artifacts.json', 'w') as f:
        json.dump(artifacts, f, indent=2)
    print("[✓] Registry artifacts saved to artifacts/registry_artifacts.json")

def cleanup_registry():
    """Run this after your project to clean up test keys"""
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, TEST_KEY_PATH)
        print("[+] Test registry keys cleaned up.")
    except:
        print("[-] Cleanup failed or already clean.")

if __name__ == '__main__':
    write_fake_registry_entries()