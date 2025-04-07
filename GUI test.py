import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Button, Label, Entry, Style
from PIL import Image, ImageTk  # Pour afficher un logo
from Test_4 import encrypt_file, decrypt_file, generate_key  # Importer les fonctions nécessaires

def browse_input_file():
    """
    Permet à l'utilisateur de sélectionner un fichier d'entrée.
    """
    file_path = filedialog.askopenfilename(title="Select Input File")
    input_file_var.set(file_path)

def browse_output_file():
    """
    Permet à l'utilisateur de sélectionner un fichier de sortie.
    """
    file_path = filedialog.asksaveasfilename(title="Select Output File")
    output_file_var.set(file_path)

def encrypt_action():
    """
    Action pour chiffrer un fichier.
    """
    input_file = input_file_var.get()
    output_file = output_file_var.get()
    if not input_file or not output_file:
        messagebox.showerror("Error", "Please select both input and output files.")
        return
    try:
        # Générer la clé et le timestamp
        key, timestamp = generate_key()
        # Chiffrer le fichier
        encrypt_file(input_file, output_file, key)
        messagebox.showinfo("Success", f"File encrypted successfully.\nKeep this key to decrypt: {timestamp}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def decrypt_action():
    """
    Action pour déchiffrer un fichier.
    """
    input_file = input_file_var.get()
    output_file = output_file_var.get()
    timestamp = timestamp_var.get()
    if not input_file or not output_file or not timestamp:
        messagebox.showerror("Error", "Please select input/output files and provide the time key.")
        return
    try:
        # Générer la clé à partir du timestamp
        key, _ = generate_key(timestamp)
        # Déchiffrer le fichier
        decrypt_file(input_file, output_file, key)
        messagebox.showinfo("Success", "File decrypted successfully.")
    except ValueError as e:
        messagebox.showerror("Error", f"Integrity check failed: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Configuration de l'interface
root = tk.Tk()
root.title("File Encryption/Decryption")
root.geometry("600x400")
root.resizable(False, False)
root.configure(bg="#f4f4f4")  # Couleur de fond

# Ajouter un logo
try:
    logo_image = Image.open("logo.png")  # Assurez-vous d'avoir un fichier logo.png dans le même dossier
    logo_image = logo_image.resize((100, 100), Image.ANTIALIAS)
    logo = ImageTk.PhotoImage(logo_image)
    logo_label = tk.Label(root, image=logo, bg="#f4f4f4")
    logo_label.pack(pady=10)
except Exception as e:
    print(f"Logo not found: {e}")

# Style professionnel
style = Style()
style.configure("TLabel", font=("Arial", 12), background="#f4f4f4")
style.configure("TButton", font=("Arial", 12), padding=5)

# Variables
input_file_var = tk.StringVar()
output_file_var = tk.StringVar()
timestamp_var = tk.StringVar()

# Widgets
Label(root, text="Input File:", style="TLabel").pack(pady=10)
Entry(root, textvariable=input_file_var, width=50, font=("Arial", 10), relief="flat").pack(pady=5)
Button(root, text="Browse", command=browse_input_file, style="TButton").pack(pady=5)

Label(root, text="Output File:", style="TLabel").pack(pady=10)
Entry(root, textvariable=output_file_var, width=50, font=("Arial", 10), relief="flat").pack(pady=5)
Button(root, text="Browse", command=browse_output_file, style="TButton").pack(pady=5)

Label(root, text="Time Key (for decryption):", style="TLabel").pack(pady=10)
Entry(root, textvariable=timestamp_var, width=50, font=("Arial", 10), relief="flat").pack(pady=5)

# Boutons pour chiffrer et déchiffrer
encrypt_button = tk.Button(
    root, text="Encrypt", command=encrypt_action, bg="#4CAF50", fg="white",
    font=("Arial", 12), relief="flat", highlightthickness=0
)
encrypt_button.pack(pady=20, ipadx=10, ipady=5)

decrypt_button = tk.Button(
    root, text="Decrypt", command=decrypt_action, bg="#2196F3", fg="white",
    font=("Arial", 12), relief="flat", highlightthickness=0
)
decrypt_button.pack(pady=10, ipadx=10, ipady=5)

# Lancer l'interface
root.mainloop()