import sys
import hashlib
import itertools
import string
import multiprocessing
import signal
import threading
import time
import functools

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

def verify_signature_with_key(file_path, key_candidate, debug=False):
    try:
        MARKER = b'--THALLIUM-META--'
        with open(file_path, 'rb') as f:
            content = f.read()
        first_split = content.rsplit(MARKER, 2)
        if len(first_split) != 3:
            if debug:
                print("[DEBUG] Mauvais format de fichier signé (pas 3 marqueurs)")
            return False
        data, meta_encrypted_block, signature_bytes = first_split
        content_to_sign = data + MARKER + meta_encrypted_block
        expected_signature = compute_hash(content_to_sign + key_candidate.encode())
        signature_str = signature_bytes.decode('utf-8').strip()
        if debug:
            print(f"[DEBUG] Clé testée: '{key_candidate}' | Signature attendue: {expected_signature} | Signature fichier: {signature_str}")
        return signature_str == expected_signature
    except Exception as e:
        if debug:
            print(f"[ERROR] Exception dans verify_signature_with_key: {e}")
        return False

tested_counter = None
last_key_value = None
log_queue = None

def try_signature_args(args):
    global tested_counter, last_key_value, log_queue
    file_path, pwd, idx, debug_mode, debug_every, log_enabled, found_flag = args
    if last_key_value is not None:
        last_key_value.value = pwd.encode()[:100]
    if found_flag.value:
        return None
    if log_enabled and log_queue is not None:
        log_queue.put(pwd)
    result = verify_signature_with_key(file_path, pwd)
    debug_this = False
    if tested_counter is not None:
        with tested_counter.get_lock():
            tested_counter.value += 1
            if debug_mode == 'debug':
                debug_this = True
            elif debug_mode == 'call' and tested_counter.value % debug_every == 0:
                debug_this = True
    if debug_this and not result and debug_mode in ('debug', 'call'):
        # On relit le fichier pour afficher le debug
        MARKER = b'--THALLIUM-META--'
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            first_split = content.rsplit(MARKER, 2)
            if len(first_split) == 3:
                data, meta_encrypted_block, signature_bytes = first_split
                content_to_sign = data + MARKER + meta_encrypted_block
                expected_signature = compute_hash(content_to_sign + pwd.encode())
                signature_str = signature_bytes.decode('utf-8').strip()
                if debug_mode == 'debug':
                    print(f"[DEBUG] {tested_counter.value} clés testées | Clé: '{pwd}' | Signature attendue: {expected_signature}")
                elif debug_mode == 'call':
                    print(f"[PROGRESS] {tested_counter.value} clés testées...")
        except Exception as e:
            print(f"[DEBUG] Erreur lors du debug: {e}")
    if result:
        found_flag.value = True
        # Arrêt immédiat de tous les workers si la clé est trouvée
        return pwd
    return None

def worker_ignore_sigint():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def bruteforce_signature(file_path, charset, min_len, max_len, show_progress=False, prefix='', log_enabled=False, log_file_path=None):
    global tested_counter, last_key_value, log_queue
    cpu_count = multiprocessing.cpu_count()
    manager = multiprocessing.Manager()
    tested_counter = multiprocessing.Value('i', 0)
    last_key_value = manager.Value('c', b'')
    stop_flag = [False]
    found_flag = manager.Value('b', False)
    found_key_shared = manager.Value('u', '')  # Ajout d'une variable partagée pour la clé trouvée
    if log_enabled:
        log_queue = manager.Queue()
        def log_writer(log_path, queue):
            with open(log_path, 'w', encoding='utf-8') as f:
                while True:
                    key = queue.get()
                    if key is None:
                        break
                    f.write(key + '\n')
        log_proc = multiprocessing.Process(target=log_writer, args=(log_file_path, log_queue))
        log_proc.start()
    else:
        log_queue = None

    # Détection du mode
    import os
    debug_mode = os.environ.get('THALLIUM_DEBUG_MODE', 'silent')
    debug_every = int(os.environ.get('THALLIUM_DEBUG_EVERY', '10000'))

    def handle_sigint(signum, frame):
        with tested_counter.get_lock():
            last_key_str = last_key_value.value.decode(errors='ignore')
            print(f"\n[INTERRUPT] {tested_counter.value} keys tested. Last tried: {last_key_str}")

    if multiprocessing.current_process().name == "MainProcess":
        signal.signal(signal.SIGINT, handle_sigint)

    # Plus de thread de progress, tout est géré dans try_signature_args

    try:
        found = False
        found_key = None
        for length in range(min_len, max_len+1):
            candidates = (''.join(candidate) for candidate in itertools.product(charset, repeat=length))
            indexed_candidates = ((file_path, pwd, idx, debug_mode, debug_every, log_enabled, found_flag) for idx, pwd in enumerate(candidates))
            worker_func = functools.partial(_try_signature_args_with_shared_key, found_key_shared=found_key_shared)
            with multiprocessing.Pool(
                cpu_count,
                initializer=worker_ignore_sigint,
            ) as pool:
                for result in pool.imap_unordered(worker_func, indexed_candidates, chunksize=10000):
                    if found_flag.value:
                        pool.terminate()
                        pool.join()
                        found = True
                        # Affichage systématique de la clé trouvée
                        key_to_show = found_key_shared.value or found_key
                        if key_to_show:
                            print(r"""
██╗  ██╗███████╗██╗   ██╗    ███████╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗     ██╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██╔════╝██╔═══██╗██║   ██║████╗  ██║██╔══██╗    ██║
█████╔╝ █████╗   ╚████╔╝     █████╗  ██║   ██║██║   ██║██╔██╗ ██║██║  ██║    ██║
██╔═██╗ ██╔══╝    ╚██╔╝      ██╔══╝  ██║   ██║██║   ██║██║╚██╗██║██║  ██║    ╚═╝
██║  ██╗███████╗   ██║       ██║     ╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝    ██╗
╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝     ╚═╝
                                                                                """)
                            print(f"[EXIT] Programme arrêté après découverte de la clé : {key_to_show}")
                        else:
                            print("[EXIT] Programme arrêté, mais la clé trouvée n'a pas pu être récupérée.")
                        sys.exit(0)
                        break
                    if result is not None:
                        print(f"[SUCCESS] Key found: {result}")
                        found_key = result
                        found_key_shared.value = result  # Mise à jour de la variable partagée
                        found_flag.value = True
                        pool.terminate()
                        pool.join()
                        print(r"""
██╗  ██╗███████╗██╗   ██╗    ███████╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗     ██╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██╔════╝██╔═══██╗██║   ██║████╗  ██║██╔══██╗    ██║
█████╔╝ █████╗   ╚████╔╝     █████╗  ██║   ██║██║   ██║██╔██╗ ██║██║  ██║    ██║
██╔═██╗ ██╔══╝    ╚██╔╝      ██╔══╝  ██║   ██║██║   ██║██║╚██╗██║██║  ██║    ╚═╝
██║  ██╗███████╗   ██║       ██║     ╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝    ██╗
╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝     ╚═╝
                                                                                """)
                        print(f"[EXIT] Programme arrêté après découverte de la clé : {result}")
                        sys.exit(0)
                        break
        stop_flag[0] = True
        if found_key or found_key_shared.value:
            print(f"[RESULT] Clé trouvée : {found_key or found_key_shared.value}")
        elif not found:
            print("No key found.")
        if log_enabled and log_queue is not None:
            log_queue.put(None)
            log_proc.join()
        if found_key or found_key_shared.value:
            return found_key or found_key_shared.value
        return None
    except Exception as e:
        stop_flag[0] = True
        if log_enabled and log_queue is not None:
            log_queue.put(None)
            log_proc.join()
        raise e

def _try_signature_args_with_shared_key(args, found_key_shared):
    result = try_signature_args(args)
    if result is not None:
        found_key_shared.value = result
    return result

def main():
    print(r"""
_____________________________________________________________________________________________________
|                ████████╗██╗  ██╗ █████╗ ██╗     ██╗     ██╗██╗   ██╗███╗   ███╗                   |
|                ╚══██╔══╝██║  ██║██╔══██╗██║     ██║     ██║██║   ██║████╗ ████║                   |
|                   ██║   ███████║███████║██║     ██║     ██║██║   ██║██╔████╔██║                   |
|                   ██║   ██╔══██║██╔══██║██║     ██║     ██║██║   ██║██║╚██╔╝██║                   |
|                   ██║   ██║  ██║██║  ██║███████╗███████╗██║╚██████╔╝██║ ╚═╝ ██║                   |
|                   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝     ╚═╝                   |
|                                                                                                   |
|    ██████╗ ██████╗ ██╗   ██╗████████╗███████╗███████╗ ██████╗ ██████╗  ██████╗███████╗██████╗     |
|    ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗    |
|    ██████╔╝██████╔╝██║   ██║   ██║   █████╗  █████╗  ██║   ██║██████╔╝██║     █████╗  ██████╔╝    |
|    ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██║     ██╔══╝  ██╔══██╗    |
|    ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗██║     ╚██████╔╝██║  ██║╚██████╗███████╗██║  ██║    |
|    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝    |
|                                                                                                   |
|__ __ __ _  _____ _ __ _ __   _ __ _ __ ___ __ ____ _ __ _  ____   _ ___  __ ___ __ _  _ ___  _ ___|
|   BruteForce - Authenticator Signature Key Recovery Tool                                          |    
|   Version 1.0 - By Arthur SAUVEZIE                                                                |
|   Licence : GNU AGPL v3                                                                           |
|  ---------------------------------------------------------                                        |
|  Usage: python3 bruteforce_signature.py <signed_file> [min_len] [max_len] [charset] [-call]       | 
|  Default: min_len=4, max_len=6, charset=letters+digits                                            |
|  ---------------------------------------------------------                                        |
|  ⚠️  Educational use only! ⚠️                                                                    |                                       
_____________________________________________________________________________________________________  
""")
    args = sys.argv[1:]
    # Demande interactive du mode si non précisé
    debug_mode = 'silent'
    debug_every = 10000
    log_enabled = False
    log_file_path = None
    # Demande à l'utilisateur le mode de fonctionnement
    print("\nModes disponibles :")
    print("  1. Normal (aucun affichage)")
    print("  2. Debug (affiche chaque clé testée)")
    print("  3. Call (affiche la progression toutes les N clés)")
    print("  4. Log (enregistre toutes les clés testées dans un fichier)")
    mode_choice = input("Choisissez le mode (1/2/3/4, plusieurs possibles séparés par une virgule, ex: 2,4) : ").strip()
    if '2' in mode_choice:
        debug_mode = 'debug'
    elif '3' in mode_choice:
        debug_mode = 'call'
    if '4' in mode_choice:
        log_enabled = True
        log_file_path = f"bruteforce_signature_{int(time.time())}.log"
        print(f"[LOG] Toutes les clés testées seront enregistrées dans : {log_file_path}")
    if debug_mode == 'call':
        try:
            debug_every = int(input("Afficher la progression toutes les combien de clés ? (défaut 10000) : ") or 10000)
        except Exception:
            debug_every = 10000

    if len(args) < 1:
        print("Aucun fichier signé fourni en argument.")
        file_path = select_file_or_folder()
        min_len = int(input("Longueur minimale de la clé (défaut 4) : ") or 4)
        max_len = int(input("Longueur maximale de la clé (défaut 6) : ") or 6)
        charset = input("Jeu de caractères (laisser vide pour lettres+chiffres+ponctuation) : ")
        if not charset:
            import string
            charset = string.ascii_letters + string.digits + string.punctuation
    else:
        file_path = args[0]
        min_len = int(args[1]) if len(args) > 1 else 4
        max_len = int(args[2]) if len(args) > 2 else 6
        charset = args[3] if len(args) > 3 else string.ascii_letters + string.digits + string.punctuation
    print(f"Bruteforcing {file_path} with charset '{charset}' and length {min_len}-{max_len}")
    # Passage du mode via variable d'environnement
    import os
    os.environ['THALLIUM_DEBUG_MODE'] = debug_mode
    os.environ['THALLIUM_DEBUG_EVERY'] = str(debug_every)
    bruteforce_signature(file_path, charset, min_len, max_len, log_enabled=log_enabled, log_file_path=log_file_path)

def test_manual_key():
    file_path = select_file_or_folder()
    key = input("Clé à tester : ").strip()
    result = verify_signature_with_key(file_path, key, debug=True)
    if result:
        print(f"[MANUAL TEST] La clé '{key}' est VALIDE pour {file_path}.")
    else:
        print(f"[MANUAL TEST] La clé '{key}' est INVALIDE pour {file_path}.")

def select_file_or_folder(base_path="."):
    import os
    exclude_files = {"authenticator.py", "bruteforce_signature.py", "bruteforce.py", "cleaner.py", "decryptor.py", "encryptor.py", "LICENSE", "README.md", "secure_bundle.py", "test.py"}
    entries = [f for f in os.listdir(base_path) if not f.startswith(".") and f not in exclude_files]
    entries = sorted(entries, key=lambda x: (os.path.isdir(os.path.join(base_path, x)), x.lower()), reverse=True)
    entries = [".. (parent directory)"] + entries
    while True:
        print("\nSélectionnez un fichier signé à bruteforcer :")
        for idx, entry in enumerate(entries):
            full_path = os.path.join(base_path, entry) if entry != ".. (parent directory)" else os.path.abspath(os.path.join(base_path, ".."))
            type_str = "[DIR]" if os.path.isdir(full_path) else "[FILE]"
            print(f"  {idx}. {entry} {type_str if entry != '.. (parent directory)' else ''}")
        try:
            choice = int(input("Votre choix (numéro) : ").strip())
            if 0 <= choice < len(entries):
                selected = entries[choice]
                if selected == ".. (parent directory)":
                    base_path = os.path.abspath(os.path.join(base_path, ".."))
                    entries = [f for f in os.listdir(base_path) if not f.startswith(".") and f not in exclude_files]
                    entries = sorted(entries, key=lambda x: (os.path.isdir(os.path.join(base_path, x)), x.lower()), reverse=True)
                    entries = [".. (parent directory)"] + entries
                    continue
                selected_path = os.path.join(base_path, selected)
                if os.path.isdir(selected_path):
                    # Entrer dans le dossier
                    base_path = selected_path
                    entries = [f for f in os.listdir(base_path) if not f.startswith(".") and f not in exclude_files]
                    entries = sorted(entries, key=lambda x: (os.path.isdir(os.path.join(base_path, x)), x.lower()), reverse=True)
                    entries = [".. (parent directory)"] + entries
                    continue
                else:
                    return selected_path
            else:
                print("Choix invalide.")
        except Exception:
            print("Entrée invalide.")

if __name__ == "__main__":
    mode = input("Mode (1=bruteforce, 2=test clé manuelle) : ").strip()
    if mode == "2":
        test_manual_key()
    else:
        main()
