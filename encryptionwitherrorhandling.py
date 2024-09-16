from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from binascii import Error as BinasciiError

# Generate a random AES key
def generate_key(key_size=16):
    return get_random_bytes(key_size)

# Encrypt plaintext using AES
def encrypt(plaintext, key):
    try:
        cipher = AES.new(key, AES.MODE_CBC)  # Create a new AES cipher with the key
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))  # Encrypt with padding
        return iv + ciphertext
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

# Decrypt ciphertext using AES
def decrypt(ciphertext, key):
    try:
        iv = ciphertext[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
        return plaintext.decode()
    except (ValueError, KeyError) as e:
        print(f"Decryption failed: {e}")
        return None

# Main function to ask for user input
def main():
    try:
        operation = input("Do you want to Encrypt or Decrypt a message? (E/D): ").strip().upper()

        if operation == "E":
            plaintext = input("Enter the plaintext to encrypt: ")
            key = generate_key()  # Generate a random AES key
            print(f"Generated Key (hex): {key.hex()}")

            encrypted_message = encrypt(plaintext, key)
            if encrypted_message:
                print(f"Encrypted message (hex): {encrypted_message.hex()}")

        elif operation == "D":
            key_hex = input("Enter the AES key (hex): ")
            try:
                key = bytes.fromhex(key_hex)  # Convert hex string back to bytes
            except BinasciiError:
                print("Invalid hex key format.")
                return

            ciphertext_hex = input("Enter the ciphertext (hex) to decrypt: ")
            try:
                ciphertext = bytes.fromhex(ciphertext_hex)  # Convert hex string back to bytes
            except BinasciiError:
                print("Invalid hex ciphertext format.")
                return

            decrypted_message = decrypt(ciphertext, key)
            if decrypted_message:
                print(f"Decrypted message: {decrypted_message}")

        else:
            print("Invalid operation. Please enter 'E' to encrypt or 'D' to decrypt.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Run the main function
if __name__ == "__main__":
    main()
