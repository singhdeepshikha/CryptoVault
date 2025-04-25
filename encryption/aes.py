from Crypto.Cipher import AES
import base64
import os

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def aes_encrypt(key, plaintext):
    key = key[:16].ljust(16)  # AES key must be 16 bytes
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_text = pad(plaintext)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt(key, ciphertext):
    key = key[:16].ljust(16)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode('utf-8').rstrip()
