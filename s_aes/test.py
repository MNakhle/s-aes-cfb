"""
Test script for S-AES encryption and decryption in the refactored structure.
"""

from encrypt import encrypt
from decrypt import decrypt

def main():
    # Test values from your example
    plaintext = 0x1234
    key = 0x5678

    # Encrypt
    ciphertext = encrypt(plaintext, key)
    print(f"Encrypted ciphertext: 0x{ciphertext:04x}")

    # Decrypt
    decrypted = decrypt(ciphertext, key)
    print(f"Decrypted plaintext: 0x{decrypted:04x}")

    # Verify
    assert decrypted == plaintext, "Decryption failed: mismatch!"
    print("Test passed: Decrypted text matches original.")

if __name__ == "__main__":
    main()
