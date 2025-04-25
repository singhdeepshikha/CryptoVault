from Crypto.Cipher import DES
import base64

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def des_encrypt(key, plaintext):
    key = key[:8].ljust(8)  # DES key must be 8 bytes
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded_text = pad(plaintext)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def des_decrypt(key, ciphertext):
    key = key[:8].ljust(8)
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode('utf-8').rstrip()
