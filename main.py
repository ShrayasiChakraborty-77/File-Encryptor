from tkinter import *
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
import os
import base64
import hashlib
import threading

def generate_key(password):
    password_bytes = password.encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(password_bytes).digest())
    return key

def confirm_overwrite(filepath):
    if os.path.exists(filepath):
        return messagebox.askyesno("Overwrite?", f"The file:\n{filepath}\nalready exists.\nDo you want to overwrite it?")
    return True

def encrypt_file_thread():
    threading.Thread(target=encrypt_file).start()

def decrypt_file_thread():
    threading.Thread(target=decrypt_file).start()

def encrypt_file():
    encrypt_btn.config(state=DISABLED)
    decrypt_btn.config(state=DISABLED)
    progress.start()
    
    file_path = file_label['text']
    password = password_entry.get()

    if not file_path or not os.path.exists(file_path):
        progress.stop()
        encrypt_btn.config(state=NORMAL)
        decrypt_btn.config(state=NORMAL)
        messagebox.showerror("Error", "Please select a valid file.")
        return
    if not password:
        progress.stop()
        encrypt_btn.config(state=NORMAL)
        decrypt_btn.config(state=NORMAL)
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        key = generate_key(password)
        fernet = Fernet(key)

        with open(file_path, 'rb') as f:
            original = f.read()

        encrypted = fernet.encrypt(original)

        save_path = file_path + ".encrypted"
        if not confirm_overwrite(save_path):
            progress.stop()
            encrypt_btn.config(state=NORMAL)
            decrypt_btn.config(state=NORMAL)
            return

        with open(save_path, 'wb') as f:
            f.write(encrypted)

        progress.stop()
        messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as:\n{save_path}")

    except Exception as e:
        progress.stop()
        messagebox.showerror("Error", f"Encryption failed.\n{str(e)}")

    encrypt_btn.config(state=NORMAL)
    decrypt_btn.config(state=NORMAL)

def decrypt_file():
    encrypt_btn.config(state=DISABLED)
    decrypt_btn.config(state=DISABLED)
    progress.start()
    
    file_path = file_label['text']
    password = password_entry.get()

    if not file_path or not os.path.exists(file_path):
        progress.stop()
        encrypt_btn.config(state=NORMAL)
        decrypt_btn.config(state=NORMAL)
        messagebox.showerror("Error", "Please select a valid file.")
        return
    if not password:
        progress.stop()
        encrypt_btn.config(state=NORMAL)
        decrypt_btn.config(state=NORMAL)
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        key = generate_key(password)
        fernet = Fernet(key)

        with open(file_path, 'rb') as f:
            encrypted = f.read()

        decrypted = fernet.decrypt(encrypted)

        new_file_path = file_path.replace(".encrypted", ".decrypted")
        if not confirm_overwrite(new_file_path):
            progress.stop()
            encrypt_btn.config(state=NORMAL)
            decrypt_btn.config(state=NORMAL)
            return

        with open(new_file_path, 'wb') as f:
            f.write(decrypted)

        progress.stop()
        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as:\n{new_file_path}")

    except Exception as e:
        progress.stop()
        messagebox.showerror("Error", f"Decryption failed.\n{str(e)}")

    encrypt_btn.config(state=NORMAL)
    decrypt_btn.config(state=NORMAL)

def browse_file():
    file_path = filedialog.askopenfilename()
    file_label.config(text=file_path)

root = Tk()
root.title("File Encryption / Decryption Tool")
root.geometry("480x320")
root.config(bg="white")

font_style = ("Arial", 12)

title_label = Label(root, text="File Encryption / Decryption Tool", font=("Arial", 16, "bold"), bg="white")
title_label.pack(pady=15)

browse_btn = Button(root, text="Choose File", command=browse_file, bg="#4caf50", fg="white", font=font_style, width=15)
browse_btn.pack()

file_label = Label(root, text="", bg="white", fg="black", wraplength=440, font=font_style)
file_label.pack(pady=5)

password_label = Label(root, text="Enter Password:", bg="white", font=font_style)
password_label.pack(pady=(15, 5))

password_entry = Entry(root, show="*", width=30, font=font_style)
password_entry.pack()

encrypt_btn = Button(root, text="Encrypt", command=encrypt_file_thread, bg="#2196f3", fg="white", font=font_style, width=15)
encrypt_btn.pack(pady=10)

decrypt_btn = Button(root, text="Decrypt", command=decrypt_file_thread, bg="#ff5722", fg="white", font=font_style, width=15)
decrypt_btn.pack(pady=5)

progress = ttk.Progressbar(root, orient=HORIZONTAL, length=300, mode='indeterminate')
progress.pack(pady=10)

root.mainloop()
