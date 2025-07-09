import sys
import hashlib
import os

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

def append_signature(file_path, secret_key):
    import json
    import datetime
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    with open(file_path, 'rb') as f:
        content = f.read()
    # Collect metadata
    now = datetime.datetime.now()
    date = now.strftime('%Y-%m-%d')
    hour = now.strftime('%H:%M:%S')
    signer = input("Signer name (optional): ").strip()
    place = input("Place (optional): ").strip()
    message = input("Message (optional): ").strip()
    meta = {
        "signer": signer,
        "date": date,
        "hour (UTC+00)": hour,
        "place": place,
        "message": message
    }
    meta_json = json.dumps(meta, ensure_ascii=False).encode('utf-8')
    # Encrypt metadata
    aesgcm = AESGCM(hashlib.sha256(secret_key.encode()).digest())
    nonce = os.urandom(12)
    meta_encrypted = aesgcm.encrypt(nonce, meta_json, None)
    MARKER = b'--THALLIUM-META--'
    meta_block = MARKER + nonce + meta_encrypted
    # Prepare content to sign (original + meta_block)
    content_to_sign = content + meta_block
    signature = compute_hash(content_to_sign + secret_key.encode())
    # Write all at once (overwrite file): content + meta_block + MARKER + signature
    with open(file_path, 'wb') as f:
        f.write(content_to_sign + MARKER + signature.encode())

def verify_signature(file_path, secret_key):
    import json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    with open(file_path, 'rb') as f:
        content = f.read()
    # Find last two nulls: ...\0nonce+meta_encrypted\0signature
    try:
        MARKER = b'--THALLIUM-META--'
        # On cherche les deux derniers marqueurs
        first_split = content.rsplit(MARKER, 2)
        if len(first_split) != 3:
            return False, None
        data, meta_encrypted_block, signature_bytes = first_split
        # meta_encrypted_block = nonce (12 bytes) + meta_encrypted
        nonce = meta_encrypted_block[:12]
        meta_encrypted = meta_encrypted_block[12:]
        aesgcm = AESGCM(hashlib.sha256(secret_key.encode()).digest())
        meta_json = aesgcm.decrypt(nonce, meta_encrypted, None)
        meta = json.loads(meta_json.decode('utf-8'))
        # To verify, hash the file up to and including the encrypted metadata (i.e. data + MARKER + meta_encrypted_block), then add secret_key
        content_to_sign = data + MARKER + meta_encrypted_block
        expected_signature = compute_hash(content_to_sign + secret_key.encode())  # hex string
        signature_str = signature_bytes.decode('utf-8').strip()
        if signature_str == expected_signature:
            return True, meta
        else:
            return False, None
    except Exception as e:
        # Debug: print(e)
        return False, None

if __name__ == "__main__":
    print(r"""
                ████████╗██╗  ██╗ █████╗ ██╗     ██╗     ██╗██╗   ██╗███╗   ███╗                          
                ╚══██╔══╝██║  ██║██╔══██╗██║     ██║     ██║██║   ██║████╗ ████║                          
                   ██║   ███████║███████║██║     ██║     ██║██║   ██║██╔████╔██║                          
                   ██║   ██╔══██║██╔══██║██║     ██║     ██║██║   ██║██║╚██╔╝██║                          
                   ██║   ██║  ██║██║  ██║███████╗███████╗██║╚██████╔╝██║ ╚═╝ ██║                          
                   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝     ╚═╝                          
                                                                                                          
 █████╗ ██╗   ██╗████████╗██╗  ██╗███████╗███╗   ██╗████████╗██╗ ██████╗ █████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║██║   ██║   ██║   ███████║█████╗  ██╔██╗ ██║   ██║   ██║██║     ███████║   ██║   ██║   ██║██████╔╝
██╔══██║██║   ██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║   ██║   ██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║╚██████╔╝   ██║   ██║  ██║███████╗██║ ╚████║   ██║   ██║╚██████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                                                           
-------------------------------------------------------------
 Authenticator - Sign and verify your files' integrity
 Version 1.0 - By Arthur SAUVEZIE
 License: GNU AGPL v3
-------------------------------------------------------------
""")
    print("What do you want to do?")
    print("1. Sign a file")
    print("2. Verify a file's signature")
    print("3. Remove signature from a file (restore original)")
    action = input("Your choice (1/2/3): ").strip()
    if action == "1":
        file_path = input("File path to sign: ").strip()
        backup_choice = input("Do you want to create a backup of the original file before signing? (y/n): ").strip().lower()
        if backup_choice == 'y':
            import shutil
            backup_path = file_path + ".bak"
            shutil.copy2(file_path, backup_path)
            print(f"Backup created: {backup_path}")
        secret_key = input("Secret key (keep it safe!): ").strip()
        append_signature(file_path, secret_key)
        print("Signature appended to the file.")
    elif action == "2":
        file_path = input("File path to verify: ").strip()
        secret_key = input("Secret key used for signing: ").strip()
        valid, meta = verify_signature(file_path, secret_key)
        if valid:
            print(r"""
Signature verification successful. The file is authentic and has not been tampered with.
Please ensure you keep the secret key safe, as it is required for future verifications.
""")
            print("Signature metadata:")
            for k, v in meta.items():
                print(f"  {k.capitalize()}: {v if v else '(not provided)'}")
        else:
            print(r"""
Signature verification failed. The file may have been tampered with or the secret key is incorrect.
Please check the file integrity and try again.
""")
    elif action == "3":
        file_path = input("File path to remove signature from: ").strip()
        MARKER = b'--THALLIUM-META--'
        with open(file_path, 'rb') as f:
            content = f.read()
        parts = content.rsplit(MARKER, 2)
        if len(parts) == 3:
            original_content = parts[0]
            with open(file_path, 'wb') as f:
                f.write(original_content)
            print("Signature removed. File restored to original content.")
        else:
            print("No signature found or file format not recognized. No changes made.")
    else:
        print("Unknown choice. Please answer 1, 2 or 3.")