import os
import sys
import hashlib
from passlib.hash import md5_crypt, sha512_crypt, sha256_crypt


def main():
    def help():
        print("Command structure \nDictionary Attack: python passwordCracker.py dictionary <algorithm (optional)> <dictionary_file> <input_file.txt> <output_file.txt> \nBrute Force Attack: python passwordCracker.py bruteforce <algorithm (optional)> <input_file.txt> <output_file.txt>")


    if len(sys.argv) < 3 or sys.argv[1] == "help":
        help()
        sys.exit()
               

    attack_mode = sys.argv[1]


    if attack_mode.lower() == "dictionary" or attack_mode.lower() == "dict":
        if len(sys.argv) == 6:
            algorithm = sys.argv[2]
            dict_file = sys.argv[3]
            input_file = sys.argv[4]
            output_file = sys.argv[5]

        elif len(sys.argv) == 5:
            algorithm = "md5"
            dict_file = sys.argv[2]
            input_file = sys.argv[3]
            output_file = sys.argv[4]

        else:
            help()
            sys.exit()


    elif attack_mode.lower() == "brute" or attack_mode.lower() == "bruteforce" or attack_mode.lower() == "brute_force" or attack_mode.lower() == "brute-force":
        if len(sys.argv) == 5:
            algorithm = sys.argv[2]
            input_file = sys.argv[3]
            output_file = sys.argv[4]

        elif len(sys.argv) == 4:
            algorithm = "md5"
            input_file = sys.argv[2]
            output_file = sys.argv[3]

        else:
            help()
            sys.exit()


    if input_file[-4:] != ".txt" or output_file[-4:] != ".txt":
        print("Invalid file type for input file and/or output file")
        sys.exit()

    if not os.path.isfile(input_file):
        print(f"Error: input file '{input_file}' does not exist.")
        sys.exit()
    
    if not os.path.isfile(output_file):
        try:
            open(output_file, 'w').close()
            print(f"Output file '{output_file}' created.")
        except OSError as e:
            print(f"Error: could not create output file '{output_file}'. {e}")
            sys.exit()

    if algorithm not in hashlib.algorithms_guaranteed:
        print("Invalid algorithm")
        sys.exit()

    if attack_mode.lower() == "dictionary" or attack_mode.lower() == "dict":
        dictionary_attack(algorithm, dict_file, input_file, output_file)
    elif attack_mode.lower() == "brute" or attack_mode.lower() == "bruteforce" or attack_mode.lower() == "brute_force" or attack_mode.lower() == "brute-force":
        brute_force_attack(algorithm, input_file, output_file)
    else:
        print("Invalid attack mode")
        sys.exit()


def detect_algorithm(hash_value):
    if hash_value.startswith('$1$'):
        return 'md5crypt'
    elif hash_value.startswith('$6$'):
        return 'sha512crypt'
    elif hash_value.startswith('$5$'):
        return 'sha256crypt'
    else:
        return 'plain'


def verify_hash(candidate, hash_value, algorithm):
    try:
        if algorithm == 'md5crypt':
            return md5_crypt.verify(candidate, hash_value)
        elif algorithm == 'sha512crypt':
            return sha512_crypt.verify(candidate, hash_value)
        elif algorithm == 'sha256crypt':
            return sha256_crypt.verify(candidate, hash_value)
        else:
            return hashlib.new(algorithm, candidate.encode()).hexdigest() == hash_value
    except Exception:
        return False


def generate_candidates(charset, length, current=""):
    if len(current) == length:
        yield current
        return
    for char in charset:
        yield from generate_candidates(charset, length, current + char)


def check_cracked_hashes(output_file): #check if output file is empty to prevent duplicate cracking
    cracked = {} # {hash: plaintext}
    try:
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue

                hash_value, plain_text = line.strip().split(':', 1)
                cracked[hash_value] = plain_text
    except OSError as e:
        print(f"Error: could not read output file '{output_file}'. {e}")
        sys.exit()


    return cracked


def dictionary_attack(algorithm, dict_file, input_file, output_file):
    cracked = check_cracked_hashes(output_file) #returns array of already cracked hashes to prevent duplicates
    try:
        with open(input_file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"Error: could not read input file '{input_file}'. {e}")
        sys.exit()

    try:
       with open(dict_file, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"Error: could not read dictionary file '{dict_file}'. {e}")
        sys.exit()

    total = len(hashes)

    uncracked = set()
    for hash_value in hashes:
        if hash_value in cracked:
            print(f"[SKIP] {hash_value} already cracked: {cracked[hash_value]}")
        else:
            uncracked.add(hash_value)

    print(f"[INFO] Starting dictionary attack with {len(words)} words...")

    for word in words:
        if not uncracked:
            break
        for hash_value in list(uncracked):
            algo = detect_algorithm(hash_value)
            if verify_hash(word, hash_value, algo):
                print(f"[FOUND] {hash_value} -> {word}")
                cracked[hash_value] = word
                uncracked.remove(hash_value)
                try:
                    with open(output_file, 'a') as out:
                        out.write(f"{hash_value}:{word}\n")
                except OSError as e:
                    print(f"Error: could not write to output file. {e}")
                    sys.exit()

    cracked_count = total - len(uncracked)
    for hash_value in uncracked:
        print(f"[FAILED] {hash_value} could not be cracked")
    print(f"\nFinished. {cracked_count}/{total} hashes cracked.")

    

def brute_force_attack(algorithm, input_file, output_file):
    cracked = check_cracked_hashes(output_file)
    try:
        with open(input_file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"Error: could not read input file '{input_file}'. {e}")
        sys.exit()

    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=+_[]{}|;:',.<>?/`~\"\\"

    max_length = 8
    total = len(hashes)

    # filter out already cracked hashes
    uncracked = set()
    for hash_value in hashes:
        if hash_value in cracked:
            print(f"[SKIP] {hash_value} already cracked: {cracked[hash_value]}")
        else:
            uncracked.add(hash_value)

    for length in range(1, max_length + 1):
        if not uncracked:
            break
        print(f"[INFO] Trying length {length}...")
        for candidate in generate_candidates(charset, length):
            for hash_value in list(uncracked):
                algo = detect_algorithm(hash_value)
                if verify_hash(candidate, hash_value, algo):
                    print(f"[FOUND] {hash_value} -> {candidate}")
                    cracked[hash_value] = candidate
                    uncracked.remove(hash_value)
                    try:
                        with open(output_file, 'a') as out:
                            out.write(f"{hash_value}:{candidate}\n")
                    except OSError as e:
                        print(f"Error: could not write to output file. {e}")
                        sys.exit()
                    if not uncracked:
                        break

    cracked_count = total - len(uncracked)
    for hash_value in uncracked:
        print(f"[FAILED] {hash_value} could not be cracked")
    print(f"\nFinished. {cracked_count}/{total} hashes cracked.")

    

if __name__== "__main__":
    main()