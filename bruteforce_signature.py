import sys
import hashlib
import itertools
import string
import multiprocessing
import signal
import threading
import time

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

def verify_signature_with_key(file_path, key_candidate):
    try:
        MARKER = b'--THALLIUM-META--'
        with open(file_path, 'rb') as f:
            content = f.read()
        first_split = content.rsplit(MARKER, 2)
        if len(first_split) != 3:
            return False
        data, meta_encrypted_block, signature_bytes = first_split
        content_to_sign = data + MARKER + meta_encrypted_block
        # Calcul de la signature attendue (hexadécimal)
        expected_signature = compute_hash(content_to_sign + key_candidate.encode())
        # Décodage de la signature du fichier (supposée être en hexadécimal)
        signature_str = signature_bytes.decode('utf-8').strip()
        # Le debug sera géré dans try_signature_args selon les options
        return signature_str == expected_signature
    except Exception as e:
        print(f"[ERROR] Exception dans verify_signature_with_key: {e}")
        return False

tested_counter = None
last_key_value = None
def try_signature_args(args):
    global tested_counter, last_key_value
    file_path, pwd, idx, debug_mode, debug_every = args
    if last_key_value is not None:
        last_key_value.value = pwd.encode()[:100]
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
        # Arrêt immédiat de tous les workers si la clé est trouvée
        return pwd
    return None

def worker_ignore_sigint():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def bruteforce_signature(file_path, charset, min_len, max_len, show_progress=False, prefix=''):
    global tested_counter, last_key_value
    cpu_count = multiprocessing.cpu_count()
    manager = multiprocessing.Manager()
    tested_counter = multiprocessing.Value('i', 0)
    last_key_value = manager.Value('c', b'')
    stop_flag = [False]

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
        for length in range(min_len, max_len+1):
            candidates = (''.join(candidate) for candidate in itertools.product(charset, repeat=length))
            indexed_candidates = ((file_path, pwd, idx, debug_mode, debug_every) for idx, pwd in enumerate(candidates))
            with multiprocessing.Pool(
                cpu_count,
                initializer=worker_ignore_sigint,
            ) as pool:
                for result in pool.imap_unordered(try_signature_args, indexed_candidates, chunksize=10000):
                    if result is not None:
                        print(f"[SUCCESS] Key found: {result}")
                        stop_flag[0] = True
                        pool.close()
                        pool.join()
                        return result
        stop_flag[0] = True
        print("No key found.")
        return None
    except Exception as e:
        stop_flag[0] = True
        raise e

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
    debug_mode = 'silent'
    debug_every = 10000
    if "-debug" in args:
        debug_mode = 'debug'
        args.remove("-debug")
    elif "-call" in args:
        debug_mode = 'call'
        args.remove("-call")
    if len(args) < 1:
        sys.exit(1)
    file_path = args[0]
    min_len = int(args[1]) if len(args) > 1 else 4
    max_len = int(args[2]) if len(args) > 2 else 6
    charset = args[3] if len(args) > 3 else string.ascii_letters + string.digits + string.punctuation
    print(f"Bruteforcing {file_path} with charset '{charset}' and length {min_len}-{max_len}")
    # Passage du mode via variable d'environnement
    import os
    os.environ['THALLIUM_DEBUG_MODE'] = debug_mode
    os.environ['THALLIUM_DEBUG_EVERY'] = str(debug_every)
    bruteforce_signature(file_path, charset, min_len, max_len)

def test_manual_key():
    file_path = "fichier.pdf"
    key = "cbaa"
    result = verify_signature_with_key(file_path, key)
    if result:
        print(f"[MANUAL TEST] La clé '{key}' est VALIDE pour {file_path}.")
    else:
        print(f"[MANUAL TEST] La clé '{key}' est INVALIDE pour {file_path}.")

if __name__ == "__main__":
    test_manual_key()
    main()
