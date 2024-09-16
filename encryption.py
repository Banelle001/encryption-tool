from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_key(key_size=16):
    return get_random_bytes(key_size)

def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext

def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext.decode()

def main():
    operation = input("Do you want to Encrypt or Decrypt a message? (E/D): ").strip().upper()

    if operation == "E":
        plaintext = input("Enter the plaintext to encrypt: ")
        key = generate_key()
        print(f"Generated Key (hex): {key.hex()}")

        encrypted_message = encrypt(plaintext, key)
        print(f"Encrypted message (hex): {encrypted_message.hex()}")

    elif operation == "D":
        key_hex = input("Enter the AES key (hex): ")
        key = bytes.fromhex(key_hex)

        ciphertext_hex = input("Enter the ciphertext (hex) to decrypt: ")
        ciphertext = bytes.fromhex(ciphertext_hex)

        decrypted_message = decrypt(ciphertext, key)
        print(f"Decrypted message: {decrypted_message}")

    else:
        print("Invalid operation. Please enter 'E' to encrypt or 'D' to decrypt.")

if __name__ == "__main__":
    main()