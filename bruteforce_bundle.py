import sys
import os
import importlib

def print_banner():
    print(r"""
 _____________________________________________________________________________________________
|                                                                                             |
|   ██████╗ ██████╗ ██╗   ██╗████████╗███████╗███████╗ ██████╗ ██████╗  ██████╗███████╗██████╗ |
|   ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗|
|   ██████╔╝██████╔╝██║   ██║   ██║   █████╗  █████╗  ██║   ██║██████╔╝██║     █████╗  ██████╔╝|
|   ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██║     ██╔══╝  ██╔══██╗|
|   ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗██║     ╚██████╔╝██║  ██║╚██████╗███████╗██║  ██║|
|   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝|
|_____________________________________________________________________________________________|
|                                                                                             |
|   BruteForce Bundle - Centralisation des outils de bruteforce                               |
|   Version 1.0 - By Arthur SAUVEZIE                                                          |
|   Licence : GNU AGPL v3                                                                     |
|_____________________________________________________________________________________________|
""")

def main():
    print_banner()
    print("\nQuel outil souhaitez-vous utiliser ?")
    print("  1. Bruteforce classique (fichiers chiffrés)")
    print("  2. Bruteforce signature (fichiers signés)")
    print("  3. Quitter")
    choix = input("Votre choix (1/2/3) : ").strip()
    if choix == "1":
        # Menu interactif pour bruteforce classique
        print("\nOptions Bruteforce classique :")
        # Sélection du fichier à bruteforcer (menu maison)
        import os
        entries = [f for f in os.listdir('.') if not f.startswith('.')]
        print("Sélectionnez un fichier ou dossier à exploiter :")
        for i, entry in enumerate(entries):
            print(f"  [{i}] {entry}")
        idx = input("Numéro : ")
        try:
            idx = int(idx)
            selected = entries[idx]
        except (ValueError, IndexError):
            print("Numéro invalide.")
            sys.exit(1)
        if os.path.isdir(selected):
            subentries = [f for f in os.listdir(selected) if not f.startswith('.')]
            print(f"Dossier '{selected}' sélectionné. Choisissez un fichier :")
            for j, sub in enumerate(subentries):
                print(f"  [{j}] {sub}")
            subidx = input("Numéro : ")
            try:
                subidx = int(subidx)
                selected = os.path.join(selected, subentries[subidx])
            except (ValueError, IndexError):
                print("Numéro invalide.")
                sys.exit(1)
        file_path = selected
        try:
            min_len = int(input("Longueur minimale de la clé (défaut 4) : ") or 4)
        except Exception:
            min_len = 4
        try:
            max_len = int(input("Longueur maximale de la clé (défaut 6) : ") or 6)
        except Exception:
            max_len = 6
        charset = input("Jeu de caractères (laisser vide pour lettres+chiffres+ponctuation) : ")
        if not charset:
            import string
            charset = string.ascii_letters + string.digits + string.punctuation
        # Options debug/progression
        print("\nModes disponibles :")
        print("  1. Normal (aucun affichage)")
        print("  2. Debug (affiche chaque clé testée)")
        print("  3. Call (affiche la progression toutes les N clés)")
        print("  4. Log (enregistre toutes les clés testées dans un fichier)")
        mode_choice = input("Choisissez le mode (1/2/3/4, plusieurs possibles séparés par une virgule, ex: 2,3) : ").strip()
        debug_mode = 'silent'
        debug_every = 10000
        extra_args = ''
        log_file = ''
        if '2' in mode_choice:
            extra_args = '-debug'
        elif '3' in mode_choice:
            extra_args = '-call'
            try:
                debug_every = int(input("Afficher la progression toutes les combien de clés ? (défaut 10000) : ") or 10000)
            except Exception:
                debug_every = 10000
            extra_args += f' {debug_every}'
        if '4' in mode_choice:
            log_file = f"bruteforce_{int(__import__('time').time())}.log"
            print(f"[LOG] Toutes les clés testées seront enregistrées dans : {log_file}")
            extra_args += f" -log {log_file}"
        # Appel du script bruteforce.py en ligne de commande avec tous les paramètres
        cmd = f"python3 bruteforce.py '{file_path}' {min_len} {max_len} '{charset}' {extra_args}"
        print(f"\n[CMD] {cmd}\n")
        os.system(cmd)
    elif choix == "2":
        # Menu interactif pour bruteforce signature
        print("\nOptions Bruteforce signature :")
        module = importlib.import_module("bruteforce_signature")
        if hasattr(module, "select_file_or_folder"):
            file_path = module.select_file_or_folder()
        else:
            file_path = input("Chemin du fichier signé à bruteforcer : ").strip()
        try:
            min_len = int(input("Longueur minimale de la clé (défaut 4) : ") or 4)
        except Exception:
            min_len = 4
        try:
            max_len = int(input("Longueur maximale de la clé (défaut 6) : ") or 6)
        except Exception:
            max_len = 6
        charset = input("Jeu de caractères (laisser vide pour lettres+chiffres+ponctuation) : ")
        if not charset:
            import string
            charset = string.ascii_letters + string.digits + string.punctuation
        print("\nModes disponibles :")
        print("  1. Normal (aucun affichage)")
        print("  2. Debug (affiche chaque clé testée)")
        print("  3. Call (affiche la progression toutes les N clés)")
        print("  4. Log (enregistre toutes les clés testées dans un fichier)")
        mode_choice = input("Choisissez le mode (1/2/3/4, plusieurs possibles séparés par une virgule, ex: 2,3) : ").strip()
        debug_mode = 'silent'
        debug_every = 10000
        log_enabled = False
        log_file_path = None
        if '2' in mode_choice:
            debug_mode = 'debug'
        elif '3' in mode_choice:
            debug_mode = 'call'
            try:
                debug_every = int(input("Afficher la progression toutes les combien de clés ? (défaut 10000) : ") or 10000)
            except Exception:
                debug_every = 10000
        if '4' in mode_choice:
            log_enabled = True
            log_file_path = f"bruteforce_signature_{int(__import__('time').time())}.log"
            print(f"[LOG] Toutes les clés testées seront enregistrées dans : {log_file_path}")
        # Passage du mode via variable d'environnement
        import os
        os.environ['THALLIUM_DEBUG_MODE'] = debug_mode
        os.environ['THALLIUM_DEBUG_EVERY'] = str(debug_every)
        # Appel de la fonction principale du module bruteforce_signature
        if hasattr(module, "bruteforce_signature"):
            module.bruteforce_signature(file_path, charset, min_len, max_len, log_enabled=log_enabled, log_file_path=log_file_path)
        elif hasattr(module, "main"):
            module.main()
        else:
            # Fallback : appel système
            extra_args = ''
            if log_enabled:
                extra_args += f" -log {log_file_path}"
            cmd = f"python3 bruteforce_signature.py '{file_path}' {min_len} {max_len} '{charset}' {extra_args}"
            print(f"\n[CMD] {cmd}\n")
            os.system(cmd)
    else:
        print("Au revoir !")
        sys.exit(0)

if __name__ == "__main__":
    main()
