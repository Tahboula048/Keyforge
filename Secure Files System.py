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

def xor_encrypt_decrypt(data, key):
    #Chiffre ou déchiffre des données binaires en utilisant XOR avec une clé.
    key_length = len(key)
    result = bytes([b ^ key[i % key_length] for i, b in enumerate(data)])
    return result

def encrypt_file(input_file, output_file, key):
    #Chiffre un fichier et écrit le résultat dans un autre fichier.
    with open(input_file, "rb") as f:
        data = f.read()  # Lire les données du fichier
    
    # Chiffrement XOR
    encrypted_data = xor_encrypt_decrypt(data, key)
    
    # Ajouter un hachage SHA-256 pour vérifier l'intégrité
    data_hash = hashlib.sha256(encrypted_data).hexdigest()
    
    # Combiner les données chiffrées et le hachage, puis encoder en Base64
    combined = encrypted_data + b":" + data_hash.encode()
    encoded = base64.b64encode(combined)
    
    # Écrire les données encodées dans le fichier de sortie
    with open(output_file, "wb") as f:
        f.write(encoded)

def decrypt_file(input_file, output_file, key):
    #Déchiffre un fichier et écrit le résultat dans un autre fichier.
    with open(input_file, "rb") as f:
        encoded = f.read()  # Lire les données encodées du fichier
    
    # Décoder les données Base64
    combined = base64.b64decode(encoded)
    
    # Séparer les données chiffrées et le hachage
    encrypted_data, data_hash = combined.rsplit(b":", 1)
    
    # Vérifier l'intégrité en recalculant le hachage
    recalculated_hash = hashlib.sha256(encrypted_data).hexdigest().encode()
    if recalculated_hash != data_hash:
        raise ValueError("The integrity of the file has been compromised.")
    
    # Déchiffrement XOR
    decrypted_data = xor_encrypt_decrypt(encrypted_data, key)
    
    # Écrire les données déchiffrées dans le fichier de sortie
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

def self_obfuscate():
    #Obfusque le script en encodant son contenu en Base64.
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
    choice = input("Do you want to encrypt or decrypt a file? (E/D): ")
    
    if choice == 'E':
        input_file = input("Enter the file path of input : ")
        output_file = input("Enter the file pah of output : ")
        key, timestamp = generate_key()
        encrypt_file(input_file, output_file, key)
        print(f"Keep the time key : {timestamp}")
    elif choice == 'D':
        input_file = input("Enter the file path of input : ")
        output_file = input("Enter the path of output : ")
        timestamp = input("Enter the time key : ")
        key, _ = generate_key(timestamp)
        try:
            decrypt_file(input_file, output_file, key)
            print("File decrypted.")
        except ValueError as e:
            print(f"Error : {e}")
    else:
        print("Invalid choice. Please enter 'E' to encrypt or 'D' to decrypt.")
    
    # Obfusque le code après exécution
    self_obfuscate()
