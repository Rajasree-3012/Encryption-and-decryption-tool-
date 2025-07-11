import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# --- Encryption Backend ---
def generate_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)

def load_key():
    with open("secret.key", "rb") as f:
        return f.read()

def encrypt_text(plain_text):
    key = load_key()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(plain_text.encode())
    return encrypted.decode()

def decrypt_text(cipher_text):
    key = load_key()
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(cipher_text.encode())
        return decrypted.decode()
    except Exception:
        return "[!] Invalid or Corrupted Encrypted Text"

# --- Main Application ---
PASSWORD = "admin123"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Encryption Tool")
        self.geometry("700x500")
        self.resizable(False, False)
        self.frames = {}
        generate_key()
        self.user_info = {}
        self.switch_frame(LoginPage)

    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self.frames:
            for frame in self.frames.values():
                frame.destroy()
        self.frames[frame_class] = new_frame
        new_frame.pack(fill="both", expand=True)

# --- Page 1: Login ---
class LoginPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#f0f0f0")
        tk.Label(self, text="Login", font=("Arial", 20, "bold"), bg="#f0f0f0").pack(pady=40)
        tk.Label(self, text="Enter Password:", font=("Arial", 12), bg="#f0f0f0").pack(pady=10)

        self.entry = tk.Entry(self, show="*", width=30, font=("Arial", 12))
        self.entry.pack(pady=5)
        self.entry.focus()

        tk.Button(self, text="Login", width=20, bg="blue", fg="white", font=("Arial", 12),
                  command=self.check_password).pack(pady=20)

    def check_password(self):
        if self.entry.get() == PASSWORD:
            self.master.switch_frame(UserInfoPage)
        else:
            messagebox.showerror("Access Denied", "Incorrect password!")

# --- Page 2: User Info ---
class UserInfoPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#f0f0f0")
        tk.Label(self, text="Enter Your Details", font=("Arial", 18, "bold"), bg="#f0f0f0").pack(pady=20)

        self.entries = {}

        fields = ["Full Name", "College Name", "Department", "Roll Number"]
        for field in fields:
            tk.Label(self, text=field + ":", font=("Arial", 12), bg="#f0f0f0").pack()
            entry = tk.Entry(self, width=50, font=("Arial", 12))
            entry.pack(pady=5)
            self.entries[field] = entry

        tk.Button(self, text="Proceed to Encryption", bg="green", fg="white", font=("Arial", 12),
                  command=self.save_and_continue).pack(pady=20)

    def save_and_continue(self):
        for field, entry in self.entries.items():
            value = entry.get().strip()
            if not value:
                messagebox.showwarning("Input Error", f"Please enter your {field}.")
                return
            self.master.user_info[field] = value

        messagebox.showinfo("Success", "Your details have been recorded.")
        self.master.switch_frame(EncryptPage)

# --- Page 3: Encrypt/Decrypt ---
class EncryptPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#f0f0f0")

        tk.Label(self, text="Input Text:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        self.input_text = tk.Text(self, height=6, width=80)
        self.input_text.pack()

        btn_frame = tk.Frame(self, bg="#f0f0f0")
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Encrypt", width=15, bg="green", fg="white", command=self.encrypt_action).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Decrypt", width=15, bg="blue", fg="white", command=self.decrypt_action).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Clear", width=15, command=self.clear_all).grid(row=0, column=2, padx=5)
        tk.Button(btn_frame, text="Copy Output", width=15, command=self.copy_to_clipboard).grid(row=0, column=3, padx=5)

        file_frame = tk.Frame(self, bg="#f0f0f0")
        file_frame.pack(pady=5)
        tk.Button(file_frame, text="Load from File", command=self.load_from_file).grid(row=0, column=0, padx=5)
        tk.Button(file_frame, text="Save to File", command=self.save_to_file).grid(row=0, column=1, padx=5)

        tk.Label(self, text="Output Text:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        self.output_text = tk.Text(self, height=6, width=80)
        self.output_text.pack()

        self.status_bar = tk.Label(self, text="Ready.", bd=1, relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 10), bg="white")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        tk.Button(self, text="Back to Login", command=lambda: master.switch_frame(LoginPage), bg="gray", fg="white").pack(pady=10)

    def encrypt_action(self):
        text = self.input_text.get("1.0", tk.END).strip()
        if text:
            encrypted = encrypt_text(text)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encrypted)
            self.update_status("Text encrypted successfully.")
        else:
            messagebox.showwarning("Input Required", "Please enter text to encrypt.")

    def decrypt_action(self):
        text = self.input_text.get("1.0", tk.END).strip()
        if text:
            decrypted = decrypt_text(text)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted)
            self.update_status("Text decrypted successfully.")
        else:
            messagebox.showwarning("Input Required", "Please enter text to decrypt.")

    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.update_status("Cleared input and output.")

    def copy_to_clipboard(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.clipboard_clear()
            self.clipboard_append(result)
            self.update_status("Copied to clipboard.")
        else:
            self.update_status("Nothing to copy.")

    def save_to_file(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
            if file:
                with open(file, "w") as f:
                    f.write(result)
                self.update_status(f"Saved to {os.path.basename(file)}.")
        else:
            self.update_status("Nothing to save.")

    def load_from_file(self):
        file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file:
            with open(file, "r") as f:
                content = f.read()
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert(tk.END, content)
                self.update_status(f"Loaded from {os.path.basename(file)}.")

    def update_status(self, message):
        self.status_bar.config(text=message)

# --- Run the App ---
if __name__ == "__main__":
    app = App()
    app.mainloop()
