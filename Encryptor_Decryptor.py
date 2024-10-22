import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
import os

class EncryptionTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption and Decryption Tool")
        
        self.key = None
        self.init_ui()
    
    def init_ui(self):
        self.file_path = tk.StringVar()
        
        tk.Label(self.root, text="File:").grid(row=0, column=0, padx=10, pady=10)
        tk.Entry(self.root, textvariable=self.file_path, width=40).grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self.root, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=10, pady=10)
        
        tk.Button(self.root, text="Generate Key", command=self.generate_key).grid(row=1, column=0, padx=10, pady=10)
        tk.Button(self.root, text="Encrypt", command=self.encrypt_file).grid(row=1, column=1, padx=10, pady=10)
        tk.Button(self.root, text="Decrypt", command=self.decrypt_file).grid(row=1, column=2, padx=10, pady=10)
    
    def browse_file(self):
        file = filedialog.askopenfilename()
        self.file_path.set(file)
    
    def generate_key(self):
        self.key = os.urandom(32)
        with open("secret.key", "wb") as key_file:
            key_file.write(self.key)
        messagebox.showinfo("Key Generated", "Key has been generated and saved as 'secret.key'.")
    
    def load_key(self):
        try:
            with open("secret.key", "rb") as key_file:
                self.key = key_file.read()
            return True
        except FileNotFoundError:
            messagebox.showwarning("Key Not Found", "Please generate a key first.")
            return False
    
    def encrypt_file(self):
        if not self.load_key():
            return
        
        if not self.file_path.get():
            messagebox.showwarning("No File", "Please select a file to encrypt.")
            return
        
        try:
            with open(self.file_path.get(), "rb") as file:
                data = file.read()
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            with open(self.file_path.get() + ".enc", "wb") as file:
                file.write(iv + encrypted_data)
            
            messagebox.showinfo("Success", "File encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def decrypt_file(self):
        if not self.load_key():
            return
        
        if not self.file_path.get():
            messagebox.showwarning("No File", "Please select a file to decrypt.")
            return
        
        try:
            with open(self.file_path.get(), "rb") as file:
                iv = file.read(16)
                encrypted_data = file.read()
            
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            with open(self.file_path.get().replace(".enc", ""), "wb") as file:
                file.write(data)
            
            messagebox.showinfo("Success", "File decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionTool(root)
    root.mainloop()

