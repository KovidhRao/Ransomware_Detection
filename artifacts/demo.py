import os, secrets

DEMO_DIR = r'C:\Users\Dell\Desktop\ransomware_forensi\artifacts'

# Step 1: Create realistic demo files
demo_files = {
    'student_thesis.docx':   b'Chapter 1: Introduction to Cybersecurity\n' * 300,
    'project_database.sql':  b'SELECT * FROM users; INSERT INTO...\n'   * 400,
    'family_photo.jpg':      b'\xff\xd8\xff\xe0' + b'JPEG data here'    * 200,
}

print("[*] BEFORE ENCRYPTION — creating demo files...")
for fname, content in demo_files.items():
    path = os.path.join(DEMO_DIR, fname)
    with open(path, 'wb') as f:
        f.write(content)
    print(f"  ✓ Created: {fname} ({len(content)} bytes)")

input("\n[Press ENTER to demonstrate encryption...]")

# Step 2: "Encrypt" using random bytes (maximum entropy)
print("\n[*] ENCRYPTING FILES (simulated)...")
for fname in demo_files:
    old_path = os.path.join(DEMO_DIR, fname)
    new_path = old_path + '.locked'
    with open(old_path, 'rb') as f:
        data = f.read()
    # Mix original data with random bytes (simulates encryption output)
    encrypted = bytes(a ^ b for a, b in zip(data, secrets.token_bytes(len(data))))
    with open(new_path, 'wb') as f:
        f.write(encrypted)
    os.remove(old_path)
    print(f"  ⚠ Encrypted: {fname} → {os.path.basename(new_path)}")

# Step 3: Drop ransom note
with open(os.path.join(DEMO_DIR, 'README_DECRYPT.txt'), 'w') as f:
    f.write("YOUR FILES ARE ENCRYPTED\nContact: attacker@darkweb.onion\nID: TEACHER-DEMO-2024")
print("\n[✓] Demo ready! Now run your forensic scanner.")
print("[→] python phase3_modules\\file_scanner.py")
print("[→] python phase3_modules\\entropy_analyzer.py")