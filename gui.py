import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from encryption import aes, des, rsa

class CryptoVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoVault - Secure Text Encryption")
        self.root.geometry("700x500")
        self.root.configure(bg="#fdf6f0")

        self.algorithm = tk.StringVar()
        self.key = tk.StringVar()
        self.result_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Title
        tk.Label(self.root, text="CryptoVault", font=("Helvetica", 20, "bold"), bg="#fdf6f0", fg="#d2691e").pack(pady=10)

        # Algorithm selection
        algo_frame = tk.Frame(self.root, bg="#fdf6f0")
        algo_frame.pack(pady=5)
        tk.Label(algo_frame, text="Select Algorithm:", font=("Helvetica", 12), bg="#fdf6f0").pack(side=tk.LEFT)
        algo_dropdown = ttk.Combobox(algo_frame, textvariable=self.algorithm, state="readonly", width=10)
        algo_dropdown['values'] = ("AES", "DES", "RSA")
        algo_dropdown.current(0)
        algo_dropdown.pack(side=tk.LEFT, padx=10)

        # Key input
        self.key_frame = tk.Frame(self.root, bg="#fdf6f0")
        self.key_frame.pack(pady=5)
        tk.Label(self.key_frame, text="Enter Key:", font=("Helvetica", 12), bg="#fdf6f0").pack(side=tk.LEFT)
        tk.Entry(self.key_frame, textvariable=self.key, width=30).pack(side=tk.LEFT, padx=10)

        # Plaintext input
        tk.Label(self.root, text="Enter Text to Encrypt:", font=("Helvetica", 12), bg="#fdf6f0").pack(pady=(15, 5))
        self.text_input = scrolledtext.ScrolledText(self.root, height=5, wrap=tk.WORD)
        self.text_input.pack(padx=20, fill=tk.X)

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#fdf6f0")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Encrypt & Decrypt", command=self.process, bg="#ff7f50", fg="white", width=20).pack()

        # Output
        tk.Label(self.root, text="Result:", font=("Helvetica", 12), bg="#fdf6f0").pack(pady=(15, 5))
        self.result_box = scrolledtext.ScrolledText(self.root, height=10, wrap=tk.WORD, bg="#fff8f0")
        self.result_box.pack(padx=20, fill=tk.BOTH, expand=True)

    def process(self):
        algo = self.algorithm.get()
        text = self.text_input.get("1.0", tk.END).strip()
        key_input = self.key.get().strip()

        if not text:
            messagebox.showerror("Input Error", "Please enter some text to encrypt.")
            return

        try:
            if algo == "AES":
                if not key_input:
                    messagebox.showerror("Key Error", "AES key is required.")
                    return
                encrypted = aes.aes_encrypt(key_input, text)
                decrypted = aes.aes_decrypt(key_input, encrypted)

            elif algo == "DES":
                if not key_input:
                    messagebox.showerror("Key Error", "DES key is required.")
                    return
                encrypted = des.des_encrypt(key_input, text)
                decrypted = des.des_decrypt(key_input, encrypted)

            elif algo == "RSA":
                priv_key, pub_key = rsa.generate_keys()
                encrypted = rsa.rsa_encrypt(pub_key, text)
                decrypted = rsa.rsa_decrypt(priv_key, encrypted)
                encrypted += f"\n\n[Public Key]\n{pub_key.decode()[:100]}..."

            else:
                raise Exception("Unsupported Algorithm")

            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, f"🔐 Encrypted:\n{encrypted}\n\n🔓 Decrypted:\n{decrypted}")

        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoVaultApp(root)
    root.mainloop()
