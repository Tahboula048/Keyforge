import os
import time
import hashlib
import getpass
import base64

def generate_key(timestamp=None):
    username = getpass.getuser()
    if timestamp is None:
        timestamp = str(int(time.time()) // 60)  # Prendre l'horodatage actuel
    disk_id = os.popen("wmic diskdrive get serialnumber").read().strip()
    
    if not disk_id:
        disk_id = "default_disk_id"

    raw_key = username + timestamp + disk_id
    hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()
    return hashed_key[:32], timestamp  # Retourne la clé et l'horodatage utilisé

def encrypt(message, key):
    shift = sum(ord(c) for c in key) % 10
    encrypted_message = ''.join(chr(ord(c) + shift) for c in message)
    return base64.b64encode(encrypted_message.encode()).decode()

def decrypt(encrypted_message, key):
    shift = sum(ord(c) for c in key) % 10
    decrypted_message = base64.b64decode(encrypted_message).decode()
    return ''.join(chr(ord(c) - shift) for c in decrypted_message)

def self_obfuscate():
    script_file = __file__
    with open(script_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    obfuscated_code = base64.b64encode(''.join(lines).encode()).decode()
    
    with open(script_file, "w", encoding="utf-8") as f:
        f.write("import base64\n")
        f.write("exec(base64.b64decode('" + obfuscated_code + "').decode())")

if __name__ == "__main__":
    choice = input("Voulez-vous (E)ncrypter ou (D)écrypter un message ? ").strip().lower()
    
    if choice == 'e':
        message = input("Entrez le message à chiffrer : ")
        key, timestamp = generate_key()
        encrypted = encrypt(message, key)
        print(f" Message chiffré : {encrypted}")
        print(f" Conservez cette valeur pour le déchiffrement : {timestamp}")
    elif choice == 'd':
        encrypted_message = input("Entrez le message à déchiffrer : ")
        timestamp = input("Entrez la clé de temps fournie lors du chiffrement : ")
        key, _ = generate_key(timestamp)
        decrypted = decrypt(encrypted_message, key)
        print(f" Message déchiffré : {decrypted}")
    else:
        print(" Choix invalide")
    
    self_obfuscate()
