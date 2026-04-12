import os, random, string
from pathlib import Path

ARTIFACTS_DIR = r'C:\Users\Dell\Desktop\ransomware_forensi\artifacts'

# Fake ransomware extensions used by real families
RANSOM_EXTENSIONS = ['.locked', '.wncry', '.enc', '.crypto', '.crypt']

RANSOM_NOTE = """YOUR FILES HAVE BEEN ENCRYPTED!
To recover your files, send 0.05 BTC to: 1A2B3C4D5E6F...
Contact: decrypt@protonmail.com
YOUR UNIQUE ID: {uid}
"""

def xor_encrypt(data, key=0x55):
    """Simulate encryption using simple XOR (NOT real encryption)"""
    return bytes([b ^ key for b in data])

def create_fake_files():
    """Create normal-looking documents to simulate"""
    file_contents = {
        'report_q1.docx': b'Quarterly financial report data... ' * 200,
        'database_backup.sql': b'INSERT INTO users VALUES ...; ' * 300,
        'photo_001.jpg': b'\xff\xd8\xff\xe0' + os.urandom(1024),
        'presentation.pptx': b'PK\x03\x04' + os.urandom(512),
        'invoice_march.pdf': b'%PDF-1.4 content here... ' * 150,
        'employee_data.xlsx': b'PK\x03\x04' + os.urandom(800),
    }
    created = []
    for fname, content in file_contents.items():
        fpath = os.path.join(ARTIFACTS_DIR, fname)
        with open(fpath, 'wb') as f:
            f.write(content)
        created.append(fpath)
        print(f"  [+] Created: {fname}")
    return created

def simulate_encryption(files):
    """Rename and XOR-encrypt each file"""
    ext = random.choice(RANSOM_EXTENSIONS)
    for fpath in files:
        with open(fpath, 'rb') as f:
            data = f.read()
        encrypted = xor_encrypt(data)
        new_path = fpath + ext
        with open(new_path, 'wb') as f:
            f.write(encrypted)
        os.remove(fpath)
        print(f"  [~] Encrypted: {os.path.basename(new_path)}")

def drop_ransom_notes():
    uid = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    note_path = os.path.join(ARTIFACTS_DIR, 'README_DECRYPT.txt')
    with open(note_path, 'w') as f:
        f.write(RANSOM_NOTE.format(uid=uid))
    print(f"  [+] Dropped ransom note (UID: {uid})")

if __name__ == '__main__':
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    print("[*] Phase 2: Simulating ransomware artifacts...")
    files = create_fake_files()
    simulate_encryption(files)
    drop_ransom_notes()
    print("[✓] Simulation complete.")