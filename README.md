

```markdown
# CryptoVault

CryptoVault is a Python-based encryption tool that provides secure text encryption and decryption using three popular encryption algorithms: AES, DES, and RSA. The application features a simple Tkinter GUI for users to interact with the encryption functions easily.

## Features

- AES Encryption/Decryption: Secure symmetric encryption using the AES (Advanced Encryption Standard) algorithm.
- DES Encryption/Decryption: Symmetric encryption using the older DES (Data Encryption Standard) algorithm.
- RSA Encryption/Decryption: Asymmetric encryption using RSA for secure key management.
- Tkinter GUI: A user-friendly interface to easily interact with the encryption algorithms.

## Prerequisites

Before you run the project, make sure you have the following:

- Python 3.10 or higher installed on your system.
- Required Python libraries (listed below).

```
## Installation
```

```
1. **Clone the repository**:
   
   If you haven't already, clone this repository to your local machine:
   
   ```bash
   git clone https://github.com/username/CryptoVault.git
   cd CryptoVault
   ```

2. **Set up a virtual environment**:
   
   It's highly recommended to use a virtual environment to manage dependencies. You can create a virtual environment using the following commands:

   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**:

   On **Windows**:
   ```bash
   .\venv\Scripts\activate
   ```

   On **macOS/Linux**:
   ```bash
   source venv/bin/activate
   ```

4. **Install the required libraries**:
   
   The project uses `pycryptodome` and `cryptography` libraries. Install them using:

   ```bash
   pip install pycryptodome cryptography
   ```

5. **Run the application**:

   To start the application, run the following command:

   ```bash
   python gui.py
   ```

## Usage

- **AES**: Enter the text you want to encrypt, choose a key size (128, 192, or 256 bits), and click "Encrypt" to encrypt the text.
- **DES**: Enter the text and a 56-bit key, then click "Encrypt" to encrypt the text.
- **RSA**: You can generate RSA keys, and use the public and private keys to encrypt and decrypt messages securely.

The user interface is simple and provides buttons for each encryption algorithm. After entering the text, you can view the encrypted/decrypted text in the output field.

## File Structure

```
CryptoVault/
├── encryption/
│   ├── aes.py         # AES encryption logic
│   ├── des.py         # DES encryption logic
│   └── rsa.py         # RSA encryption logic
├── gui.py             # Tkinter GUI interface
├── main.py            # main script
└── README.md          # Project description
```

