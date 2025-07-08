import os
import sys
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password)

def encrypt_file(filepath: str, password: str, output_dir: str):
    # Read file data
    with open(filepath, 'rb') as f:
        data = f.read()

    # Generate salt and nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)

    # Derive key
    key = derive_key(password.encode(), salt)

    # Encrypt data
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)

    # Prepare output path in data directory, preserving relative structure
    rel_path = os.path.relpath(filepath, start=DATA_ROOT)
    outpath = os.path.join(output_dir, rel_path + '.enc')
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'wb') as f:
        f.write(salt + nonce + encrypted)
    print(f"Encrypted file: {outpath}")
if __name__ == "__main__":
    # Set data root and output directory
    DATA_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
    OUTPUT_ROOT = DATA_ROOT  # Output encrypted files to data as well

    print(r"""
    _________________________________________________________________
    |     _____  _   _   ___   _      _     _____  _   _ ___  ___   |
    |    |_   _|| | | | / _ \ | |    | |   |_   _|| | | ||  \/  |   |
    |      | |  | |_| |/ /_\ \| |    | |     | |  | | | || .  . |   |
    |      | |  |  _  ||  _  || |    | |     | |  | | | || |\/| |   |
    |      | |  | | | || | | || |____| |_____| |_ | |_| || |  | |   |
    |      \_/  \_| |_/|_| |_/\_____/\_____/\___/  \___/ \_|  |_/   |
    |       _____                                  _                |
    |      |  ___|                                | |               |
    |      | |__  _ __    ___  _ __  _   _  _ __  | |_  ___   _ __  |
    |      |  __|| '_ \  / __|| '__|| | | || '_ \ | __|/ _ \ | '__| |
    |      | |___| | | || (__ | |   | |_| || |_) || |_| (_) || |    |
    |      \____/|_| |_| \___||_|    \__, || .__/  \__|\___/ |_|    |
    |                                 __/ || |                      |
    |                                |___/ |_|                      |
    |  _____  _   _   ___   ___  ___  ___  ___  ___  ___  ___  ___  |
    |  Encryptor - A tool for encrypting files and folders          |
    |  Version 1.0 - By Arthur SAUVEZIE                             |
    |  License: Apache 2.0 - https://www.apache.org/                |
    |  Warning: Use this tool at your own risk.                     |
    |  Usage: python3 encryptor.py                                  |
    _________________________________________________________________                                              
""")
    import base64
    choice = input("Do you want to encrypt a file or a folder? (f/d): ").strip().lower()
    if choice == 'f':
        filepath = input("Path to the file to encrypt (relative to data/): ").strip()
        abs_filepath = os.path.join(DATA_ROOT, filepath)
        if not os.path.isfile(abs_filepath):
            print("File not found.")
            exit(1)
        confirm = input(f"Do you confirm the encryption of '{abs_filepath}'? (y/n): ").lower()
        if confirm != 'y':
            print("Operation cancelled.")
            exit(0)
        key_mode = input("Do you want to set the key yourself? (y/n): ").strip().lower()
        if key_mode == 'y':
            password = getpass("Enter the encryption key: ")
            password2 = getpass("Confirm the encryption key: ")
            if password != password2:
                print("Keys do not match.")
                exit(1)
        else:
            password = base64.urlsafe_b64encode(os.urandom(32)).decode()
            keyfile = abs_filepath + '.key'
            with open(keyfile, 'w') as f:
                f.write(password)
            print(f"Key generated and saved in: {keyfile}")
        encrypt_file(abs_filepath, password, OUTPUT_ROOT)
    elif choice == 'd':
        dirpath = input("Path to the folder to encrypt (relative to data/): ").strip()
        abs_dirpath = os.path.join(DATA_ROOT, dirpath)
        if not os.path.isdir(abs_dirpath):
            print("Folder not found.")
            exit(1)
        confirm = input(f"Do you confirm the encryption of all files in the folder and its subfolders '{abs_dirpath}'? (y/n): ").lower()
        if confirm != 'y':
            print("Operation cancelled.")
            exit(0)
        key_mode = input("Do you want to use the same key for all files (1), a different key for each file (2), or auto-generate a key and save it in a file (3)? (1/2/3): ").strip()
        if key_mode == '1':
            password = getpass("Enter the encryption key: ")
            password2 = getpass("Confirm the encryption key: ")
            if password != password2:
                print("Keys do not match.")
                exit(1)
            def get_password(_):
                return password
        elif key_mode == '2':
            def get_password(fpath):
                pwd = base64.urlsafe_b64encode(os.urandom(32)).decode()
                keyfile = fpath + '.key'
                with open(keyfile, 'w') as f:
                    f.write(pwd)
                print(f"Key generated and saved in: {keyfile}")
                return pwd
        elif key_mode == '3':
            # Auto-generate one key for the whole folder, save it in a file
            password = base64.urlsafe_b64encode(os.urandom(32)).decode()
            keyfile = os.path.join(abs_dirpath, 'FOLDER.key')
            with open(keyfile, 'w') as f:
                f.write(password)
            print(f"Key generated and saved in: {keyfile}")
            def get_password(_):
                return password
        else:
            print("Invalid choice. Please answer with '1', '2', or '3'.")
            sys.exit(1)
        for root, _, files in os.walk(abs_dirpath):
            for name in files:
                fpath = os.path.join(root, name)
                if fpath.endswith('.enc') or fpath.endswith('.key'):
                    continue  # Do not encrypt already encrypted files or keys
                print(f"Encrypting: {fpath}")
                encrypt_file(fpath, get_password(fpath), OUTPUT_ROOT)
        print("All files in the folder and its subfolders have been encrypted.")
    else:
        print("Invalid choice. Please answer with 'f' or 'd'.")
        sys.exit(1)
        sys.exit(1)
