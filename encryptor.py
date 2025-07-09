import os
import sys
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password)

def encrypt_file(filepath: str, password: str, output_dir: str, use_salt=True):
    # Read file data
    with open(filepath, 'rb') as f:
        data = f.read()

    # Generate salt and nonce
    salt = os.urandom(16) if use_salt else b''
    nonce = os.urandom(12)

    # Derive key
    key = derive_key(password.encode(), salt) if use_salt else derive_key(password.encode(), b'\x00'*16)

    # Encrypt data
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)

    # Prepare output path in data directory, preserving relative structure
    rel_path = os.path.relpath(filepath, start=DATA_ROOT)
    outpath = os.path.join(output_dir, rel_path + '.enc')
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'wb') as f:
        f.write(salt + nonce + encrypted if use_salt else nonce + encrypted)
    print(f"Encrypted file: {outpath}")
def select_file_or_folder():
    import os
    import sys
    exclude_files = {"authenticator.py", "bruteforce_signature.py", "bruteforce.py", "cleaner.py", "decryptor.py", "encryptor.py", "LICENSE", "README.md", "secure_bundle.py", "test.py"}
    base_path = '.'
    entries = [f for f in os.listdir(base_path) if not f.startswith(".") and f not in exclude_files]
    entries = sorted(entries, key=lambda x: (os.path.isdir(os.path.join(base_path, x)), x.lower()), reverse=True)
    entries = [".. (parent directory)"] + entries
    while True:
        print("\nSélectionnez un fichier ou dossier à chiffrer :")
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
                entries = [f for f in os.listdir(base_path) if not f.startswith(".") and f not in exclude_files]
                entries = sorted(entries, key=lambda x: (os.path.isdir(os.path.join(base_path, x)), x.lower()), reverse=True)
                entries = [".. (parent directory)"] + entries
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
    # Set data root and output directory to current directory
    DATA_ROOT = os.path.abspath(os.getcwd())
    OUTPUT_ROOT = DATA_ROOT  # Output encrypted files to current directory

    use_salt = True
    if "-light" in sys.argv:
        use_salt = False
        sys.argv.remove("-light")

    print(r"""
_____________________________________________________________________________________
|        ████████╗██╗  ██╗ █████╗ ██╗     ██╗     ██╗██╗   ██╗███╗   ███╗           |      
|        ╚══██╔══╝██║  ██║██╔══██╗██║     ██║     ██║██║   ██║████╗ ████║           |     
|           ██║   ███████║███████║██║     ██║     ██║██║   ██║██╔████╔██║           |      
|           ██║   ██╔══██║██╔══██║██║     ██║     ██║██║   ██║██║╚██╔╝██║           |      
|           ██║   ██║  ██║██║  ██║███████╗███████╗██║╚██████╔╝██║ ╚═╝ ██║           |      
|           ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝     ╚═╝           |      
|                                                                                   |  
|    ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗   | 
|    ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗  |
|    █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██████╔╝  |
|    ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██╔══██╗  |
|    ███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║  ██║  |
|    ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝  |
|__ __ __ _  _____ _ __ _ __   _ __ _ ____ _ __ _  ____   _ ___  __ ___  _ ___  _ __|
|                                                                                   |
|  Encryptor - A tool for encrypting files and folders                              |
|  Version 1.0 - By Arthur SAUVEZIE                                                 |
|  License: GNU AFFERO 3                                                            |
|  Warning: Use this tool at your own risk.                                         |
|  Usage: python3 encryptor.py                                                      |
_____________________________________________________________________________________                                              
""")
    import base64
    # Sélection interactive
    selected, is_folder = select_file_or_folder()
    if is_folder:
        dirpath = selected
        abs_dirpath = os.path.join(DATA_ROOT, dirpath)
        if not os.path.isdir(abs_dirpath):
            print("Folder not found.")
            exit(1)
        confirm = input(f"Do you confirm the encryption of all files in the folder and its subfolders '{abs_dirpath}'? (y/n): ").lower()
        if confirm != 'y':
            print("Operation cancelled.")
            exit(0)
        keyfile_paths = []
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
                keyfile_paths.append(keyfile)
                return pwd
        elif key_mode == '3':
            password = base64.urlsafe_b64encode(os.urandom(32)).decode()
            keyfile = os.path.join(abs_dirpath, 'FOLDER.key')
            with open(keyfile, 'w') as f:
                f.write(password)
            print(f"Key generated and saved in: {keyfile}")
            keyfile_paths.append(keyfile)
            def get_password(_):
                return password
        else:
            print("Invalid choice. Please answer with '1', '2', or '3'.")
            sys.exit(1)
        encrypted_files = []
        for root, _, files in os.walk(abs_dirpath):
            for name in files:
                fpath = os.path.join(root, name)
                if fpath.endswith('.enc') or fpath.endswith('.key'):
                    continue  # Do not encrypt already encrypted files or keys
                print(f"Encrypting: {fpath}")
                encrypt_file(fpath, get_password(fpath), OUTPUT_ROOT, use_salt)
                encrypted_files.append(fpath)
        print("All files in the folder and its subfolders have been encrypted.")
        # Demander suppression des fichiers originaux
        delete_choice = input("\nVoulez-vous supprimer TOUS les fichiers originaux pour ne conserver que les fichiers chiffrés et les clefs (si elles sont dans des fichiers) ? (y/n): ").strip().lower()
        if delete_choice == 'y':
            print("\nATTENTION : Si vous supprimez les fichiers originaux et perdez les clefs, il sera impossible de récupérer vos données !")
            confirm_delete = input("Confirmez-vous la suppression de TOUS les fichiers originaux ? (y/n): ").strip().lower()
            if confirm_delete == 'y':
                for f in encrypted_files:
                    try:
                        os.remove(f)
                        print(f"Fichier original supprimé : {f}")
                    except Exception as e:
                        print(f"Erreur lors de la suppression de {f} : {e}")
            else:
                print("Suppression annulée.")
        else:
            print("Les fichiers originaux ont été conservés.")
    else:
        filepath = selected
        abs_filepath = os.path.join(DATA_ROOT, filepath)
        if not os.path.isfile(abs_filepath):
            print("File not found.")
            exit(1)
        confirm = input(f"Do you confirm the encryption of '{abs_filepath}'? (y/n): ").lower()
        if confirm != 'y':
            print("Operation cancelled.")
            exit(0)
        keyfile = None
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
        encrypt_file(abs_filepath, password, OUTPUT_ROOT, use_salt)
        # Demander suppression du fichier original
        delete_choice = input("\nVoulez-vous supprimer le fichier original pour ne conserver que le fichier chiffré et la clef (si elle est dans un fichier) ? (y/n): ").strip().lower()
        if delete_choice == 'y':
            print("\nATTENTION : Si vous supprimez le fichier original et perdez la clef, il sera impossible de récupérer vos données !")
            confirm_delete = input("Confirmez-vous la suppression du fichier original ? (y/n): ").strip().lower()
            if confirm_delete == 'y':
                try:
                    os.remove(abs_filepath)
                    print(f"Fichier original supprimé : {abs_filepath}")
                except Exception as e:
                    print(f"Erreur lors de la suppression : {e}")
            else:
                print("Suppression annulée.")
        else:
            print("Le fichier original a été conservé.")
