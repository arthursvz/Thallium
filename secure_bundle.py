

# --- Dépendances internes ---
import os
import sys
import hashlib
import base64
import json
import datetime
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password)

def encrypt_file(filepath: str, password: str, output_dir: str, use_salt=True, data_root=None):
    with open(filepath, 'rb') as f:
        data = f.read()
    salt = os.urandom(16) if use_salt else b''
    nonce = os.urandom(12)
    key = derive_key(password.encode(), salt) if use_salt else derive_key(password.encode(), b'\x00'*16)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)
    if data_root is None:
        data_root = os.path.abspath(os.getcwd())
    rel_path = os.path.relpath(filepath, start=data_root)
    outpath = os.path.join(output_dir, rel_path + '.enc')
    outdir = os.path.dirname(outpath)
    if outdir and not os.path.exists(outdir):
        os.makedirs(outdir, exist_ok=True)
    with open(outpath, 'wb') as f:
        f.write(salt + nonce + encrypted if use_salt else nonce + encrypted)
    print(f"Encrypted file: {outpath}")
    return outpath

def decrypt_file(encrypted_file_path, password, output_file_path):
    with open(encrypted_file_path, 'rb') as f:
        filedata = f.read()
    if len(filedata) >= 28:
        salt = filedata[:16]
        nonce = filedata[16:28]
        ciphertext = filedata[28:]
    else:
        salt = b'\x00' * 16
        nonce = filedata[:12]
        ciphertext = filedata[12:]
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    with open(output_file_path, 'wb') as f:
        f.write(decrypted)

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

def append_signature(file_path, secret_key):
    with open(file_path, 'rb') as f:
        content = f.read()
    now = datetime.datetime.now()
    date = now.strftime('%Y-%m-%d')
    hour = now.strftime('%H:%M:%S')
    # Accept meta as argument for batch mode
    raise NotImplementedError("Use append_signature_with_meta for batch processing.")

def append_signature_with_meta(file_path, secret_key, meta):
    import datetime
    now = datetime.datetime.now()
    date = now.strftime('%Y-%m-%d')
    hour = now.strftime('%H:%M:%S')
    meta = dict(meta)  # copy
    meta['date'] = date
    meta['hour (UTC+00)'] = hour
    meta_json = json.dumps(meta, ensure_ascii=False).encode('utf-8')
    aesgcm = AESGCM(hashlib.sha256(secret_key.encode()).digest())
    nonce = os.urandom(12)
    MARKER = b'--THALLIUM-META--'
    meta_encrypted = aesgcm.encrypt(nonce, meta_json, None)
    meta_block = MARKER + nonce + meta_encrypted
    with open(file_path, 'rb') as f:
        content = f.read()
    content_to_sign = content + meta_block
    signature = compute_hash(content_to_sign + secret_key.encode())
    with open(file_path, 'wb') as f:
        f.write(content_to_sign + MARKER + signature.encode())

def verify_signature(file_path, secret_key):
    with open(file_path, 'rb') as f:
        content = f.read()
    try:
        MARKER = b'--THALLIUM-META--'
        first_split = content.rsplit(MARKER, 2)
        if len(first_split) != 3:
            return False, None
        data, meta_encrypted_block, signature_bytes = first_split
        nonce = meta_encrypted_block[:12]
        meta_encrypted = meta_encrypted_block[12:]
        aesgcm = AESGCM(hashlib.sha256(secret_key.encode()).digest())
        meta_json = aesgcm.decrypt(nonce, meta_encrypted, None)
        meta = json.loads(meta_json.decode('utf-8'))
        content_to_sign = data + MARKER + meta_encrypted_block
        expected_signature = compute_hash(content_to_sign + secret_key.encode())
        signature_str = signature_bytes.decode('utf-8').strip()
        if signature_str == expected_signature:
            return True, meta
        else:
            return False, None
    except Exception as e:
        return False, None

def encrypt_and_sign(filepath, key):
    import os
    def process_file(fpath, key, data_root, meta):
        output_dir = os.path.dirname(fpath)
        encrypted_path = encrypt_file(fpath, key, output_dir, data_root=data_root)
        append_signature_with_meta(encrypted_path, key, meta)
        print(f"Encrypted File : {encrypted_path}")
    # Ask meta only once
    signer = input("Signer name (optional): ").strip()
    place = input("Place (optional): ").strip()
    message = input("Message (optional): ").strip()
    meta = {"signer": signer, "place": place, "message": message}
    # Ask once for deletion
    delete_choice = input("Do you want to delete the original file(s)? (y/N): ").strip().lower()
    delete_confirmed = False
    if delete_choice == 'y':
        print("WARNING: If you delete the original file(s) and lose the key, the file(s) will be permanently inaccessible!")
        confirm = input("Are you sure you want to delete the original file(s)? (y/N): ").strip().lower()
        if confirm == 'y':
            delete_confirmed = True
    if os.path.isdir(filepath):
        data_root = os.path.abspath(filepath)
        print(f"Recursively encrypting all files in directory: {filepath}")
        for root, dirs, files in os.walk(filepath):
            for file in files:
                full_path = os.path.join(root, file)
                process_file(full_path, key, data_root, meta)
                if delete_confirmed:
                    try:
                        os.remove(full_path)
                        print(f"Original file deleted: {full_path}")
                    except Exception as e:
                        print(f"Error deleting original file: {e}")
    else:
        data_root = os.path.abspath(os.getcwd())
        if not os.path.isfile(filepath):
            print(f"Error: File not found: {filepath}")
            return
        process_file(filepath, key, data_root, meta)
        if delete_confirmed:
            try:
                os.remove(filepath)
                print(f"Original file deleted: {filepath}")
            except Exception as e:
                print(f"Error deleting original file: {e}")

def verify_and_decrypt(filepath, key):
    import os
    def process_decrypt_file(fpath, key, delete_confirmed, keyfile_to_delete=None):
        valid, meta = verify_signature(fpath, key)
        if not valid:
            print(f"Corrupted File ! ({fpath})")
            return
        print(f"Valid sign for {fpath}. Metadata :")
        for k, v in meta.items():
            print(f"  {k.capitalize()}: {v if v else '(non renseigné)'}")
        # Extraire la partie chiffrée d'origine (avant le premier marqueur)
        MARKER = b'--THALLIUM-META--'
        with open(fpath, 'rb') as f:
            content = f.read()
        parts = content.split(MARKER, 1)
        if len(parts) < 2:
            print(f"File Format Error: No encrypted data found in {fpath}.")
            return
        encrypted_data = parts[0]
        # Sauvegarder temporairement la partie chiffrée
        temp_enc_path = fpath + '.tmp_onlyenc'
        with open(temp_enc_path, 'wb') as f:
            f.write(encrypted_data)
        # Générer le nom de sortie : DECOD_nom_fichier.extension
        base = os.path.basename(fpath)
        if base.endswith('.enc'):
            base = base[:-4]
        output_path = os.path.join(os.path.dirname(fpath), f"DECOD_{base}")
        try:
            decrypt_file(temp_enc_path, key, output_path)
            print(f"Decrypted File : {output_path}")
        finally:
            os.remove(temp_enc_path)

        if delete_confirmed:
            try:
                if os.path.isfile(fpath):
                    os.remove(fpath)
                    print(f"Deleted: {fpath}")
                # Delete the key file only once, after all files if in batch mode
                if keyfile_to_delete:
                    if os.path.isfile(keyfile_to_delete):
                        os.remove(keyfile_to_delete)
                        print(f"Deleted: {keyfile_to_delete}")
            except Exception as e:
                print(f"Error deleting files: {e}")

    # Ask once for deletion
    delete_choice = input("Do you want to delete the encoded file(s) and the key (.key)? (y/N): ").strip().lower()
    delete_confirmed = False
    if delete_choice == 'y':
        print("WARNING: If you delete the .key file and lose the key, you will NEVER be able to decrypt the file again!")
        confirm = input("Are you sure you want to delete the .enc and .key files? (y/N): ").strip().lower()
        if confirm == 'y':
            delete_confirmed = True

    if os.path.isdir(filepath):
        print(f"Recursively decrypting all .enc files in directory: {filepath}")
        # Key file for a directory: <directory>.key (not inside the directory)
        keyfile_to_delete = filepath.rstrip('/\\') + '.key'
        enc_files = []
        for root, dirs, files in os.walk(filepath):
            for file in files:
                if file.endswith('.enc'):
                    full_path = os.path.join(root, file)
                    enc_files.append(full_path)
        for idx, full_path in enumerate(enc_files):
            # Delete key file only after last file
            process_decrypt_file(full_path, key, delete_confirmed, keyfile_to_delete if delete_confirmed and idx == len(enc_files)-1 else None)
    else:
        # For a single file, delete its .key file
        if filepath.endswith('.enc'):
            keyfile_to_delete = filepath[:-4] + '.key'
        else:
            keyfile_to_delete = filepath + '.key'
        process_decrypt_file(filepath, key, delete_confirmed, keyfile_to_delete if delete_confirmed else None)


def main():
    print("""
==== Secure Bundle (Encrypt + Sign) ====
1. Encrypt and Sign a file
2. Verify and Decrypt a signed file
""")
    action = input("your choice (1/2): ").strip()
    if action == "1":
        import os
        file_path = input("File or directory to encrypt and sign: ").strip()
        key_mode = input("Do you want to provide the key (1) or generate and save it in a .key file (2)? (1/2): ").strip()
        if key_mode == '2':
            import base64
            import secrets
            key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
            # Always save the key as <directory>.key or <file>.key (never .enc.key)
            if os.path.isdir(file_path):
                keyfile = file_path.rstrip('/\\') + '.key'
            else:
                keyfile = file_path + '.key'
            with open(keyfile, 'w') as f:
                f.write(key)
            print(f"Key generated and saved in: {keyfile}")
        else:
            key = input("Encryption/signature key: ").strip()
        encrypt_and_sign(file_path, key)
    elif action == "2":
        file_path = input("File to verify and decrypt: ").strip()
        key_mode = input("Is the key in a .key file? (y/N): ").strip().lower()
        if key_mode == 'y':
            # Always look for the key as the original file name with .key (not .enc.key)
            import os
            import base64
            def is_valid_key(keystr):
                try:
                    key_bytes = base64.urlsafe_b64decode(keystr.encode())
                    return len(key_bytes) == 32
                except Exception:
                    return False
            # If the file ends with .enc, remove it for key file lookup
            if file_path.endswith('.enc'):
                keyfile = file_path[:-4] + '.key'
            else:
                keyfile = file_path + '.key'
            import base64
            def is_valid_key(keystr):
                try:
                    key_bytes = base64.urlsafe_b64decode(keystr.encode())
                    return len(key_bytes) == 32
                except Exception:
                    return False
            while True:
                if not os.path.isfile(keyfile):
                    print(f"Key file not found at: {keyfile}")
                    keyfile = input("Please provide the path to the key file: ").strip()
                    continue
                try:
                    with open(keyfile, 'r') as f:
                        key = f.read().strip()
                    if not is_valid_key(key):
                        print(f"Key file found at {keyfile}, but the key format is invalid. It must be a base64-encoded 32-byte key.")
                        keyfile = input("Please provide the path to the key file: ").strip()
                        continue
                    print(f"Key loaded from: {keyfile}")
                    break
                except Exception as e:
                    print(f"Error reading key file: {e}")
                    keyfile = input("Please provide the path to the key file: ").strip()
        else:
            key = input("Encryption/signature key: ").strip()
        verify_and_decrypt(file_path, key)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
