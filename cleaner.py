import os

def is_key_file(filename):
    key_extensions = ['.key', '.pem', '.crt', '.cer', '.der', '.pfx', '.p12']
    return any(filename.lower().endswith(ext) for ext in key_extensions)

def is_encrypted_file(filename):
    encrypted_extensions = ['.enc', '.gpg', '.aes', '.crypt', '.vault']
    return any(filename.lower().endswith(ext) for ext in encrypted_extensions)

def confirm_and_delete(filepath):
    resp = input(f"Supprimer '{filepath}' ? (o/N): ").strip().lower()
    if resp == 'o':
        try:
            os.remove(filepath)
            print(f"Supprimé: {filepath}")
        except Exception as e:
            print(f"Erreur lors de la suppression de {filepath}: {e}")
    else:
        print(f"Conservé: {filepath}")


def clean_folder(folder):
    for root, _, files in os.walk(folder):
        for filename in files:
            filepath = os.path.join(root, filename)
            if is_key_file(filename) or is_encrypted_file(filename):
                confirm_and_delete(filepath)

def main():
    import sys
    DATA_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
    if len(sys.argv) > 1:
        rel_folder = sys.argv[1]
        folder = os.path.join(DATA_ROOT, rel_folder)
    else:
        folder = DATA_ROOT
    if not os.path.isdir(folder):
        print(f"Folder not found: {folder}")
        return
    clean_folder(folder)

if __name__ == "__main__":
    main()
