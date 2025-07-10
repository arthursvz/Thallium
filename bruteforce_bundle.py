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
        # Sélection du fichier à bruteforcer
        module = importlib.import_module("bruteforce")
        if hasattr(module, "select_file_or_folder"):
            file_path = module.select_file_or_folder()
        else:
            file_path = input("Chemin du fichier à bruteforcer : ").strip()
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
        mode_choice = input("Choisissez le mode (1/2/3, plusieurs possibles séparés par une virgule, ex: 2,3) : ").strip()
        debug_mode = 'silent'
        debug_every = 10000
        if '2' in mode_choice:
            debug_mode = 'debug'
        elif '3' in mode_choice:
            debug_mode = 'call'
        if debug_mode == 'call':
            try:
                debug_every = int(input("Afficher la progression toutes les combien de clés ? (défaut 10000) : ") or 10000)
            except Exception:
                debug_every = 10000
        # Passage du mode via variable d'environnement
        os.environ['THALLIUM_DEBUG_MODE'] = debug_mode
        os.environ['THALLIUM_DEBUG_EVERY'] = str(debug_every)
        # Appel de la fonction principale du module bruteforce
        if hasattr(module, "bruteforce_file"):
            module.bruteforce_file(file_path, charset, min_len, max_len)
        elif hasattr(module, "main"):
            # Si main() gère les arguments interactifs, on passe par main
            module.main()
        else:
            # Fallback : appel système
            os.system(f"python3 bruteforce.py '{file_path}' {min_len} {max_len} '{charset}'")
    elif choix == "2":
        module = importlib.import_module("bruteforce_signature")
        if hasattr(module, "main"):
            module.main()
        else:
            os.system(f"python3 bruteforce_signature.py")
    else:
        print("Au revoir !")
        sys.exit(0)

if __name__ == "__main__":
    main()
