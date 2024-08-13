from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ciphertext = base64.b64encode(ciphertext_bytes).decode('utf-8')
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    iv_decoded = base64.b64decode(iv)
    ciphertext_decoded = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv_decoded)
    decrypted_bytes = cipher.decrypt(ciphertext_decoded)
    plaintext = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
    return plaintext

if __name__ == "__main__":
    key = get_random_bytes(16)  # 128-bit key
    plaintext = input("Enter the plaintext: ")

    iv, ciphertext = aes_encrypt(key, plaintext)
    print("Ciphertext:", ciphertext)

    decrypted_text = aes_decrypt(key, iv, ciphertext)
    print("Decrypted text:", decrypted_text)
