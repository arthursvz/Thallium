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

def select_file_or_folder(base_path="."):
    import os
    import sys
    exclude_files = {"authenticator.py", "bruteforce_signature.py", "bruteforce.py", "cleaner.py", "decryptor.py", "encryptor.py", "LICENSE", "README.md", "secure_bundle.py", "test.py"}
    while True:
        entries = [f for f in os.listdir(base_path) if not f.startswith(".") and f not in exclude_files]
        entries = sorted(entries, key=lambda x: (os.path.isdir(os.path.join(base_path, x)), x.lower()), reverse=True)
        entries = [".. (parent directory)"] + entries
        print("\nSélectionnez un fichier ou dossier à déchiffrer :")
        for i, entry in enumerate(entries):
            full_path = os.path.join(base_path, entry) if entry != ".. (parent directory)" else os.path.abspath(os.path.join(base_path, ".."))
            type_str = "[DIR]" if os.path.isdir(full_path) else "[FILE]"
            print(f"  [{i}] {entry} {type_str if entry != '.. (parent directory)' else ''}")
        idx = input("Numéro : ")
        try:
            idx = int(idx)
            selected = entries[idx]
            if selected == ".. (parent directory)":
                base_path = os.path.abspath(os.path.join(base_path, ".."))
                continue
            selected_path = os.path.join(base_path, selected)
            if os.path.isdir(selected_path):
                subentries = [f for f in os.listdir(selected_path) if not f.startswith(".") and f not in exclude_files]
                print(f"Dossier '{selected}' sélectionné. Choisissez un fichier ou validez pour tout le dossier :")
                for j, sub in enumerate(subentries):
                    print(f"  [{j}] {sub}")
                subidx = input("Numéro (laisser vide pour tout le dossier) : ")
                if subidx.strip() == '':
                    return selected_path, True
                try:
                    subidx = int(subidx)
                    selected_path = os.path.join(selected_path, subentries[subidx])
                    return selected_path, False
                except (ValueError, IndexError):
                    print("Numéro invalide.")
                    continue
            return selected_path, False
        except (ValueError, IndexError):
            print("Numéro invalide.")
            continue

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
    # Sélection interactive
    selected, is_folder = select_file_or_folder()
    if not is_folder:
        encrypted_file = selected
        abs_encrypted_file = os.path.join(DATA_ROOT, encrypted_file)
        # ...existing code...
        # (remplacer la demande de chemin par abs_encrypted_file)
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
    else:
        dirpath = selected
        abs_dirpath = os.path.join(DATA_ROOT, dirpath)
        # ...existing code...
        # (remplacer la demande de chemin par abs_dirpath)
