import os
import time
import hashlib
import getpass
import base64

# He generate a key
def generate_key(timestamp=None):
    username = getpass.getuser() # He get the username of the current user
    if timestamp is None:
        timestamp = str(int(time.time()) // 60)  # He get the current timestamp in minutes
    disk_id = os.popen("wmic diskdrive get serialnumber").read().strip() # He get the disk ID
    
    if not disk_id:
        disk_id = "default_disk_id"

    raw_key = username + timestamp + disk_id # He does a combination of the username, timestamp and disk ID
    hashed_key = hashlib.sha256(raw_key.encode()).digest()  # He hash the key using SHA-256
    return hashed_key, timestamp  

def xor_encrypt_decrypt(data, key):
    #Encrypts or decrypts binary data using XOR with a key.
    key_length = len(key)
    result = bytes([b ^ key[i % key_length] for i, b in enumerate(data)]) # XOR operation with a key length
    return result

def encrypt_file(input_file, output_file, key):
    #Encrypts a file and writes the result to another file.
    with open(input_file, "rb") as f:
        data = f.read()  # Read the binary data from the input file
    
    
    encrypted_data = xor_encrypt_decrypt(data, key)
    
    # Hash the data for integrity check
    # He hash the data using SHA-256
    data_hash = hashlib.sha256(encrypted_data).hexdigest()
    
    # Combine the encrypted data and the hash, then encode into Base64
    combined = encrypted_data + b":" + data_hash.encode()
    encoded = base64.b64encode(combined)
    
    # Write the encoded data to the output file
    with open(output_file, "wb") as f:
        f.write(encoded)

def decrypt_file(input_file, output_file, key):
    # Decrypts a file and writes the result to another file.
    with open(input_file, "rb") as f:
        encoded = f.read()  # Lire les données encodées du fichier
    
    # Decode Base64 data
    combined = base64.b64decode(encoded)
    
    # Separate encrypted data and hash
    encrypted_data, data_hash = combined.rsplit(b":", 1)
    
    # Check integrity by recalculating the hash
    recalculated_hash = hashlib.sha256(encrypted_data).hexdigest().encode()
    if recalculated_hash != data_hash:
        raise ValueError("The integrity of the file has been compromised.")
    

    decrypted_data = xor_encrypt_decrypt(encrypted_data, key)
    
    # Write the decrypted data to the output file
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

def self_obfuscate():
    # Obfuscates the script by encoding its contents in Base64.
    script_file = __file__  # Gets the path of the current file
    with open(script_file, "r", encoding="utf-8") as f:
        lines = f.read()  # Reads the entire contents of the script
    
    # Encodes the entire script to Base64
    obfuscated_code = base64.b64encode(lines.encode()).decode()
    
    # Rewrite the script to run the obfuscated code
    with open(script_file, "w", encoding="utf-8") as f:
        f.write("import base64\n")
        f.write("exec(base64.b64decode('''" + obfuscated_code + "''').decode())")


# Main function to run the script
if __name__ == "__main__":
    choice = input("Do you want to encrypt or decrypt a file? (E/D): ")
    
    # Encryption
    if choice == 'E':
        input_file = input("Enter the file path of input : ")
        output_file = input("Enter the file pah of output : ")
        key, timestamp = generate_key() # He generate the key
        encrypt_file(input_file, output_file, key)
        print(f"Keep the time key : {timestamp}") # He give the time key
    #  Decrytion
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
    
    # Obfuscation
    self_obfuscate()
