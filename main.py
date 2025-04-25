from encryption import aes, des, rsa

def main():
    print("\n--- CryptoVault: Secure Text Encryption ---")
    print("Choose Encryption Algorithm:")
    print("1. AES")
    print("2. DES")
    print("3. RSA")

    choice = input("Enter choice (1/2/3): ")
    plaintext = input("Enter the text to encrypt: ")

    if choice == '1':
        key = input("Enter AES Key (16 chars or less): ")
        encrypted = aes.aes_encrypt(key, plaintext)
        decrypted = aes.aes_decrypt(key, encrypted)
    elif choice == '2':
        key = input("Enter DES Key (8 chars or less): ")
        encrypted = des.des_encrypt(key, plaintext)
        decrypted = des.des_decrypt(key, encrypted)
    elif choice == '3':
        priv_key, pub_key = rsa.generate_keys()
        encrypted = rsa.rsa_encrypt(pub_key, plaintext)
        decrypted = rsa.rsa_decrypt(priv_key, encrypted)
        print("\n🔑 RSA Public Key:\n", pub_key.decode())
        print("🔒 RSA Private Key:\n", priv_key.decode())
    else:
        print("Invalid choice.")
        return

    print(f"\n🔐 Encrypted Text:\n{encrypted}")
    print(f"🔓 Decrypted Text:\n{decrypted}")

if __name__ == "__main__":
    main()
