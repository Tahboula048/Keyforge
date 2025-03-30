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
    hashed_key = hashlib.sha256(raw_key.encode()).digest()  # Génère un hachage SHA-256
    return hashed_key, timestamp  # Retourne une clé de 32 octets et l'horodatage utilisé

def xor_encrypt_decrypt(message, key):
    """Chiffre ou déchiffre un message en utilisant XOR avec une clé."""
    key_length = len(key)
    result = ''.join(chr(ord(c) ^ key[i % key_length]) for i, c in enumerate(message))
    return result

def encrypt(message, key):
    """Chiffre un message avec XOR et ajoute un hachage pour l'intégrité."""
    # Chiffrement XOR
    encrypted_message = xor_encrypt_decrypt(message, key)
    
    # Ajouter un hachage SHA-256 pour vérifier l'intégrité
    message_hash = hashlib.sha256(encrypted_message.encode()).hexdigest()
    
    # Combiner le message chiffré et le hachage, puis encoder en Base64
    combined = f"{encrypted_message}:{message_hash}"
    return base64.b64encode(combined.encode()).decode()

def decrypt(encrypted_message, key):
    """Déchiffre un message avec XOR et vérifie l'intégrité."""
    # Décoder le message Base64
    combined = base64.b64decode(encrypted_message).decode()
    
    # Séparer le message chiffré et le hachage
    encrypted_message, message_hash = combined.rsplit(":", 1)
    
    # Vérifier l'intégrité en recalculant le hachage
    recalculated_hash = hashlib.sha256(encrypted_message.encode()).hexdigest()
    if recalculated_hash != message_hash:
        raise ValueError("L'intégrité du message a été compromise.")
    
    # Déchiffrement XOR
    decrypted_message = xor_encrypt_decrypt(encrypted_message, key)
    return decrypted_message

def self_obfuscate():
    """Obfusque le script en encodant son contenu en Base64."""
    script_file = __file__  # Récupère le chemin du fichier actuel
    with open(script_file, "r", encoding="utf-8") as f:
        lines = f.read()  # Lit tout le contenu du script
    
    # Encode le script entier en Base64
    obfuscated_code = base64.b64encode(lines.encode()).decode()
    
    # Réécrit le script pour qu'il exécute le code obfusqué
    with open(script_file, "w", encoding="utf-8") as f:
        f.write("import base64\n")
        f.write("exec(base64.b64decode('''" + obfuscated_code + "''').decode())")

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
        try:
            decrypted = decrypt(encrypted_message, key)
            print(f" Message déchiffré : {decrypted}")
        except ValueError as e:
            print(f"Erreur : {e}")
    else:
        print(" Choix invalide")
    
    # Obfusque le code après exécution
    self_obfuscate()
    print("Le code a été obfusqué.")