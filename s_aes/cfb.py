"""
cfb.py - Implements Cipher Feedback (CFB) mode encryption and decryption
for Simplified AES (S-AES).
"""

from .core import key_expansion
from .encrypt import encrypt
from .utils import blocks_to_text, int_to_state, state_to_int, text_to_blocks


def cfb_encrypt(text, key, iv):
    """
    Encrypts a list of plaintext blocks using CFB mode.

    Args:
        plaintext : String to be encrypted.
        key (int): 16-bit encryption key.
        iv (int): 16-bit initialization vector.

    Returns:
        list of int: Encrypted ciphertext blocks.
    """

    plaintext_blocks = text_to_blocks(text)
    round_keys = key_expansion(key)
    ciphertext_blocks = []
    prev = iv
    

    for plaintext in plaintext_blocks:
        # Encrypt the previous block (IV or previous ciphertext)
        prev_state = int_to_state(prev)
        encrypted = encrypt(state_to_int(prev_state), round_keys)
        encrypted_int = encrypted

        # XOR with plaintext to get ciphertext
        ciphertext = plaintext ^ encrypted_int
        ciphertext_blocks.append(ciphertext)

        # Update previous block
        prev = ciphertext

    return ciphertext_blocks


def cfb_decrypt(ciphertext_blocks, key, iv):
    """
    Decrypts a list of ciphertext blocks using CFB mode.

    Args:
        ciphertext_blocks (list of int): List of 16-bit ciphertext blocks.
        key (int): 16-bit encryption key.
        iv (int): 16-bit initialization vector.

    Returns:
        list of int: Decrypted plaintext blocks.
    """
    round_keys = key_expansion(key)
    plaintext_blocks = []
    prev = iv

    for ciphertext in ciphertext_blocks:
        # Encrypt the previous block (IV or previous ciphertext)
        prev_state = int_to_state(prev)
        encrypted = encrypt(state_to_int(prev_state), round_keys)
        encrypted_int = encrypted

        # XOR with ciphertext to get plaintext
        plaintext = ciphertext ^ encrypted_int
        plaintext_blocks.append(plaintext)

        # Update previous block
        prev = ciphertext

    return blocks_to_text(plaintext_blocks)
