import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import itertools
import string
import multiprocessing
import signal
import threading
import time

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password)

def try_decrypt(filedata, password_candidate, debug_mode='silent', debug_every=10000, idx=0, found_flag=None, found_password=None):
    if found_flag is not None and found_flag.value:
        return None
    salt = filedata[:16]
    nonce = filedata[16:28]
    ciphertext = filedata[28:]
    try:
        key = derive_key(password_candidate.encode(), salt)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        if found_flag is not None:
            found_flag.value = 1
        if found_password is not None:
            found_password.value = password_candidate
        if debug_mode == 'debug' and (found_flag is None or not found_flag.value):
            print(f"[DEBUG] Clé testée: '{password_candidate}' | Salt: {salt.hex()} | Index: {idx}")
        elif debug_mode == 'call' and idx % debug_every == 0 and (found_flag is None or not found_flag.value):
            print(f"[PROGRESS] {idx} clés testées...")
        return decrypted
    except Exception:
        if debug_mode == 'debug' and (found_flag is None or not found_flag.value):
            print(f"[DEBUG] Clé testée: '{password_candidate}' | Salt: {salt.hex()} | Index: {idx} | ECHEC")
        return None

tested_counter = None
last_key_value = None
def try_decrypt_args(args):
    global tested_counter, last_key_value
    filedata, pwd, idx, debug_mode, debug_every, found_flag, found_password = args
    if last_key_value is not None:
        last_key_value.value = pwd.encode()[:100]
    result = try_decrypt(filedata, pwd, debug_mode, debug_every, idx, found_flag, found_password)
    if tested_counter is not None:
        with tested_counter.get_lock():
            tested_counter.value += 1
    if result is not None:
        return (pwd, result)
    return None
def worker_ignore_sigint():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

class KeyFound(Exception):
    pass

def bruteforce(enc_path, charset, min_len, max_len, output_file=None, show_progress=False):
    global tested_counter, last_key_value
    cpu_count = multiprocessing.cpu_count()
    with open(enc_path, 'rb') as f:
        filedata = f.read()
    manager = multiprocessing.Manager()
    tested_counter = multiprocessing.Value('i', 0)
    last_key_value = manager.Value('c', b'')
    stop_flag = [False]
    found_flag = manager.Value('i', 0)
    found_password = manager.Value('u', '')

    # Modes debug/call/silent
    import os
    debug_mode = os.environ.get('THALLIUM_DEBUG_MODE', 'silent')
    debug_every = int(os.environ.get('THALLIUM_DEBUG_EVERY', '10000'))

    def handle_sigint(signum, frame):
        with tested_counter.get_lock():
            last_key_str = last_key_value.value.decode(errors='ignore')
            print(f"\n[INTERRUPT] {tested_counter.value} clés testées. Dernière clé essayée : {last_key_str}")

    if multiprocessing.current_process().name == "MainProcess":
        signal.signal(signal.SIGINT, handle_sigint)

    t = None
    if show_progress or debug_mode == 'call':
        def progress_thread():
            last = 0
            while not stop_flag[0]:
                with tested_counter.get_lock():
                    current = tested_counter.value
                if debug_mode == 'call':
                    if current // debug_every > last // debug_every:
                        print(f"[PROGRESS] {current} clés testées...")
                        last = current
                else:
                    print(f"[PROGRESS] {current} clés testées...")
                time.sleep(0.5)
        t = threading.Thread(target=progress_thread, daemon=True)
        t.start()

    try:
        found_pwd = None
        for length in range(min_len, max_len+1):
            candidates = (''.join(candidate) for candidate in itertools.product(charset, repeat=length))
            indexed_candidates = ((filedata, pwd, idx, debug_mode, debug_every, found_flag, found_password) for idx, pwd in enumerate(candidates))
            with multiprocessing.Pool(
                cpu_count,
                initializer=worker_ignore_sigint,
            ) as pool:
                for result in pool.imap_unordered(try_decrypt_args, indexed_candidates, chunksize=10000):
                    if found_flag.value:
                        stop_flag[0] = True
                        if t:
                            t.join(timeout=1)
                        if found_password.value:
                            #print(f"[SUCCESS] Password found: {found_password.value}")
                            print(r"""
██╗  ██╗███████╗██╗   ██╗    ███████╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗     ██╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██╔════╝██╔═══██╗██║   ██║████╗  ██║██╔══██╗    ██║
█████╔╝ █████╗   ╚████╔╝     █████╗  ██║   ██║██║   ██║██╔██╗ ██║██║  ██║    ██║
██╔═██╗ ██╔══╝    ╚██╔╝      ██╔══╝  ██║   ██║██║   ██║██║╚██╗██║██║  ██║    ╚═╝
██║  ██╗███████╗   ██║       ██║     ╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝    ██╗
╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝     ╚═╝
                                                                                """)
                            print(f"[EXIT] Programme arrêté après découverte de la clé : {found_password.value}")
                        else:
                            print("[EXIT] Programme arrêté après découverte de la clé (clé non récupérée)")
                        pool.terminate()
                        sys.exit(0)
                    if result is not None:
                        pwd, decrypted = result
                        stop_flag[0] = True
                        found_flag.value = 1
                        found_password.value = pwd
                        if t:
                            t.join(timeout=1)
                        print(f"[SUCCESS] Password found: {pwd}")
                        print(f"[EXIT] Programme arrêté après découverte de la clé : {pwd}")
                        pool.terminate()
                        sys.exit(0)
        stop_flag[0] = True
        if t:
            t.join(timeout=1)
        print("No password found.")
        return None
    except Exception as e:
        stop_flag[0] = True
        if t:
            t.join(timeout=1)
        raise e

def init_counter(counter):
    global tested_counter
    tested_counter = counter

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
|   BruteForce - Testeur de mots de passe chiffrés AES-GCM                                          |    
|   Version 1.0 - By Arthur SAUVEZIE                                                                |
|   Licence : GNU AGPL v3                                                                           |
|  ---------------------------------------------------------                                        |
|  Usage: python3 bruteforce.py <file.enc> [min_len] [max_len] [charset] [output_file] [-call] [-debug]|
|  Default: min_len=1, max_len=4, charset=all printable ASCII (letters, digits, specials)           |
|  ---------------------------------------------------------                                        |
|  ⚠️  Usage pédagogique uniquement ! ⚠️                                                           |                                       
_____________________________________________________________________________________________________  
""")
    show_progress = False
    args = sys.argv[1:]
    debug_mode = 'silent'
    debug_every = 10000
    if "-debug" in args:
        debug_mode = 'debug'
        args.remove("-debug")
    elif "-call" in args:
        debug_mode = 'call'
        idx = args.index("-call")
        args.remove("-call")
        # Si un nombre suit -call, on le prend comme debug_every
        if len(args) > idx and args[idx].isdigit():
            debug_every = int(args[idx])
            args.pop(idx)
    if len(args) < 1:
        sys.exit(1)
    enc_path = args[0]
    min_len = int(args[1]) if len(args) > 1 else 1
    max_len = int(args[2]) if len(args) > 2 else 20
    default_charset = string.ascii_letters + string.digits + string.punctuation
    charset = args[3] if len(args) > 3 else default_charset
    output_file = args[4] if len(args) > 4 else None
    print(f"Bruteforcing {enc_path} with charset '{charset}' and length {min_len}-{max_len}")
    # Passage du mode via variable d'environnement
    import os
    os.environ['THALLIUM_DEBUG_MODE'] = debug_mode
    os.environ['THALLIUM_DEBUG_EVERY'] = str(debug_every)
    bruteforce(enc_path, charset, min_len, max_len, output_file, show_progress)

if __name__ == "__main__":
    main()
