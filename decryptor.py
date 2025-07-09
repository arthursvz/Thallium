## Ancienne fonction non utilisée, à supprimer :
# def load_key(key_path):
# def decrypt_file(encrypted_file_path, key_path, output_file_path):
import os
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password)

def decrypt_file(encrypted_file_path, password, output_file_path):
    with open(encrypted_file_path, 'rb') as f:
        filedata = f.read()
    # Détection automatique : avec ou sans salt
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

def try_decrypt(filedata, password_candidate):
    # Détection automatique : si le fichier commence par 16 octets de salt (mode normal), sinon mode -light
    if len(filedata) >= 28:
        salt = filedata[:16]
        nonce = filedata[16:28]
        ciphertext = filedata[28:]
    else:
        salt = b'\x00' * 16
        nonce = filedata[:12]
        ciphertext = filedata[12:]
    try:
        key = derive_key(password_candidate.encode(), salt)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted
    except Exception as e:
        print("Erreur de déchiffrement :", e)
        return None

if __name__ == "__main__":
    # Set data root to current directory
    DATA_ROOT = os.path.abspath(os.getcwd())

    print(r"""
_____________________________________________________________________________________
|        ████████╗██╗  ██╗ █████╗ ██╗     ██╗     ██╗██╗   ██╗███╗   ███╗           |
|        ╚══██╔══╝██║  ██║██╔══██╗██║     ██║     ██║██║   ██║████╗ ████║           |
|           ██║   ███████║███████║██║     ██║     ██║██║   ██║██╔████╔██║           |
|           ██║   ██╔══██║██╔══██║██║     ██║     ██║██║   ██║██║╚██╔╝██║           |
|           ██║   ██║  ██║██║  ██║███████╗███████╗██║╚██████╔╝██║ ╚═╝ ██║           |
|           ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝     ╚═╝           |
|                                                                                   |
|    ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗     |
|    ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗    |
|    ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██████╔╝    |
|    ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██╔══██╗    |
|    ██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║  ██║    |
|    ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝    |
|                                                                                   |
|__ __ __ _  _____ _ __ _ __   _ __ _ ____ _ __ _  ____   _ ___  __ ___  _ ___  _ __|
|                                                                                   |
|  Encryptor - A tool for decypting files and folders                               |
|  Version 1.0 - By Arthur SAUVEZIE                                                 |
|  License: GNU AFFERO 3                                                            |
|  Warning: Use this tool at your own risk.                                         |
|  Usage: python3 decryptor.py                                                      |
_____________________________________________________________________________________                 
""")
    import sys
    choice = input("Do you want to decrypt a file or a folder? (f/d): ").strip().lower()
    if choice == 'f':
        encrypted_file = input("Path to the encrypted file (relative to current directory): ").strip()
        abs_encrypted_file = os.path.join(DATA_ROOT, encrypted_file)
        key_input_mode = input("Is the decryption key in a file? (y/n): ").strip().lower()
        if key_input_mode == 'y':
            # Try to automatically detect the key file
            if abs_encrypted_file.endswith('.enc'):
                key_file_guess = abs_encrypted_file[:-4] + '.key'
            else:
                key_file_guess = abs_encrypted_file + '.key'
            if os.path.isfile(key_file_guess):
                key_file = key_file_guess
                print(f"Key automatically detected: {key_file}")
            else:
                key_file = input("Path to the key file (relative to current directory): ").strip()
                key_file = os.path.join(DATA_ROOT, key_file)
            with open(key_file, 'r') as f:
                password = f.read().strip()
        else:
            password = getpass("Enter the decryption key: ")
        # Automatically determine the decoded file name
        if abs_encrypted_file.endswith('.enc'):
            original_name = abs_encrypted_file[:-4]
        else:
            original_name = abs_encrypted_file
        dirname = os.path.dirname(original_name)
        basename = os.path.basename(original_name)
        output_file = os.path.join(dirname, 'DECOD_' + basename)
        try:
            decrypt_file(abs_encrypted_file, password, output_file)
            print(f"File successfully decrypted: {output_file}")
        except Exception as e:
            print(f"Error during decryption: {e}")
        # Offer to clean up associated .enc and .key files
        resp = input("Do you want to delete the encrypted (.enc) and key (.key) files? (y/N): ").strip().lower()
        if resp == 'y':
            # Only delete the .enc and .key files, NOT the decoded or original file
            for f in [abs_encrypted_file, abs_encrypted_file[:-4] + '.key']:
                if os.path.isfile(f):
                    try:
                        os.remove(f)
                        print(f"Deleted: {f}")
                    except Exception as e:
                        print(f"Error deleting {f}: {e}")
    elif choice == 'd':
        dirpath = input("Path to the folder to decrypt (relative to current directory): ").strip()
        abs_dirpath = os.path.join(DATA_ROOT, dirpath)
        if not os.path.isdir(abs_dirpath):
            print("Folder not found.")
            sys.exit(1)
        confirm = input(f"Do you confirm the decryption of all .enc files in the folder '{abs_dirpath}'? (y/n): ").lower()
        if confirm != 'y':
            print("Operation cancelled.")
            sys.exit(0)
        key_mode = input("How were the files encrypted? Same key for all (1), different key for each file (2), or main key file (3)? (1/2/3): ").strip()
        if key_mode == '1':
            password = getpass("Enter the decryption key common to all files: ")
            def get_password(_):
                return password
        elif key_mode == '2':
            def get_password(fpath):
                keyfile = os.path.splitext(fpath)[0] + '.key'
                if not os.path.isfile(keyfile):
                    print(f"Missing key for {fpath}: {keyfile}")
                    return None
                with open(keyfile, 'r') as f:
                    return f.read().strip()
        elif key_mode == '3':
            # Try to find FOLDER.key in the folder
            keyfile = os.path.join(abs_dirpath, 'FOLDER.key')
            if not os.path.isfile(keyfile):
                print(f"Main key file not found: {keyfile}")
                sys.exit(1)
            with open(keyfile, 'r') as f:
                password = f.read().strip()
            def get_password(_):
                return password
        else:
            print("Invalid choice. Please answer with '1', '2', or '3'.")
            sys.exit(1)
        decrypted_files = []
        for root, _, files in os.walk(abs_dirpath):
            for name in files:
                if not name.endswith('.enc'):
                    continue
                fpath = os.path.join(root, name)
                # Get the original file name before encryption
                if fpath.endswith('.enc'):
                    original_name = fpath[:-4]
                else:
                    original_name = fpath
                dirname = os.path.dirname(original_name)
                basename = os.path.basename(original_name)
                outpath = os.path.join(dirname, 'DECOD_' + basename)
                pwd = get_password(fpath)
                if not pwd:
                    print(f"File skipped (missing key): {fpath}")
                    continue
                try:
                    decrypt_file(fpath, pwd, outpath)
                    print(f"Decrypted: {fpath} -> {outpath}")
                    decrypted_files.append((fpath, original_name + '.key'))
                except Exception as e:
                    print(f"Error for {fpath}: {e}")
        print("All files in the folder have been processed.")
        # Offer to clean up associated .enc and .key files
        resp = input("Do you want to delete the associated .enc and .key files? (y/N): ").strip().lower()
        if resp == 'y':
            for fenc, fkey in decrypted_files:
                for f in [fenc, fkey]:
                    if os.path.isfile(f):
                        try:
                            os.remove(f)
                            print(f"Deleted: {f}")
                        except Exception as e:
                            print(f"Error deleting {f}: {e}")
    else:
        print("Invalid choice. Please answer with 'f' or 'd'.")
        sys.exit(1)
        sys.exit(1)
