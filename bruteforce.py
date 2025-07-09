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

def try_decrypt(filedata, password_candidate):
    salt = filedata[:16]
    nonce = filedata[16:28]
    ciphertext = filedata[28:]
    try:
        key = derive_key(password_candidate.encode(), salt)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted
    except Exception:
        return None

tested_counter = None
last_key_value = None
def try_decrypt_args(args):
    global tested_counter, last_key_value
    filedata, pwd, idx = args
    if last_key_value is not None:
        last_key_value.value = pwd.encode()[:100]  # Limite la taille pour éviter les débordements
    result = try_decrypt(filedata, pwd)
    if tested_counter is not None:
        with tested_counter.get_lock():
            tested_counter.value += 1
    if result is not None:
        return (pwd, result)
    return None
def worker_ignore_sigint():
    signal.signal(signal.SIGINT, signal.SIG_IGN)
def bruteforce(enc_path, charset, min_len, max_len, output_file=None, show_progress=False):
    global tested_counter, last_key_value
    cpu_count = multiprocessing.cpu_count()
    with open(enc_path, 'rb') as f:
        filedata = f.read()
    manager = multiprocessing.Manager()
    tested_counter = multiprocessing.Value('i', 0)
    last_key_value = manager.Value('c', b'')
    stop_flag = [False]

    def handle_sigint(signum, frame):
        with tested_counter.get_lock():
            last_key_str = last_key_value.value.decode(errors='ignore')
            print(f"\n[INTERRUPT] {tested_counter.value} clés testées. Dernière clé essayée : {last_key_str}")

    if multiprocessing.current_process().name == "MainProcess":
        signal.signal(signal.SIGINT, handle_sigint)

    def progress_thread():
        while not stop_flag[0]:
            with tested_counter.get_lock():
                print(f"[PROGRESS] {tested_counter.value} clés testées...")
            time.sleep(5)

    t = None
    if show_progress:
        t = threading.Thread(target=progress_thread, daemon=True)
        t.start()

    try:
        for length in range(min_len, max_len+1):
            candidates = (''.join(candidate) for candidate in itertools.product(charset, repeat=length))
            indexed_candidates = ((filedata, pwd, idx) for idx, pwd in enumerate(candidates))
            with multiprocessing.Pool(
                cpu_count,
                initializer=worker_ignore_sigint,
            ) as pool:
                for result in pool.imap_unordered(try_decrypt_args, indexed_candidates, chunksize=10000):
                    if result is not None:
                        pwd, decrypted = result
                        print(f"[SUCCESS] Password found: {pwd}")
                        if output_file:
                            with open(output_file, 'wb') as f:
                                f.write(decrypted)
                        else:
                            print(decrypted)
                        stop_flag[0] = True
                        pool.close()   # <-- Arrêt propre du pool
                        pool.join()    # <-- Attend la fin des workers
                        if t:
                            t.join(timeout=1)
                        return pwd
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
|  Usage: python3 bruteforce.py <file.enc> [min_len] [max_len] [charset] [output_file] [-call]      | 
|  Default: min_len=1, max_len=4, charset=all printable ASCII (letters, digits, specials)           |
|  ---------------------------------------------------------                                        |
|  ⚠️  Usage pédagogique uniquement ! ⚠️                                                           |                                       
_____________________________________________________________________________________________________  
""")
    show_progress = False
    args = sys.argv[1:]
    if "-call" in args:
        show_progress = True
        args.remove("-call")
    if len(args) < 1:
        sys.exit(1)
    enc_path = args[0]
    min_len = int(args[1]) if len(args) > 1 else 1
    max_len = int(args[2]) if len(args) > 2 else 20
    default_charset = string.ascii_letters + string.digits + string.punctuation
    charset = args[3] if len(args) > 3 else default_charset
    output_file = args[4] if len(args) > 4 else None
    print(f"Bruteforcing {enc_path} with charset '{charset}' and length {min_len}-{max_len}")
    bruteforce(enc_path, charset, min_len, max_len, output_file, show_progress)

if __name__ == "__main__":
    main()
