import os

def should_keep(filename):
    keep_extensions = ['.py']
    keep_names = ['README', 'README.md', 'LICENSE', 'LICENSE.txt']
    base = os.path.basename(filename)
    if base.lower() in [n.lower() for n in keep_names]:
        return True
    if any(base.lower().endswith(ext) for ext in keep_extensions):
        return True
    return False

def confirm_and_delete(filepath):
    import sys
    if '-brute' in sys.argv:
        try:
            os.remove(filepath)
            print(f"Supprimé: {filepath}")
        except Exception as e:
            print(f"Erreur lors de la suppression de {filepath}: {e}")
    else:
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
        # Ignore tout ce qui est dans .git
        if '.git' in root.split(os.sep):
            continue
        for filename in files:
            filepath = os.path.join(root, filename)
            if not should_keep(filename):
                confirm_and_delete(filepath)
            else:
                print(f"Conservé: {filepath}")

def main():
    import sys
    DATA_ROOT = os.path.abspath(os.getcwd())
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    if args:
        rel_folder = args[0]
        folder = os.path.join(DATA_ROOT, rel_folder)
    else:
        folder = DATA_ROOT
    if not os.path.isdir(folder):
        print(f"Folder not found: {folder}")
        return
    clean_folder(folder)

if __name__ == "__main__":
    main()
