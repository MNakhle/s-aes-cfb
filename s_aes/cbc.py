from s_aes import decrypt, encrypt
from s_aes.core import key_expansion
from s_aes.utils import blocks_to_text, text_to_blocks


def cbc_encrypt(plaintext: str, key: int, iv: int) -> list[int]:
    """
    Encrypts plaintext using S-AES in CBC mode.
    
    Args:
        plaintext: String to encrypt (UTF-8 encoded)
        key: 16-bit encryption key
        iv: 16-bit initialization vector
        
    Returns:
        List of ciphertext blocks (as 16-bit integers)
    """
    blocks = text_to_blocks(plaintext)
    round_keys = key_expansion(key)
    ciphertext_blocks = []
    prev_cipher = iv
    
    for plaintext_block in blocks:
        # XOR with previous ciphertext (or IV for first block)
        xor_result = plaintext_block ^ prev_cipher
        
        # Encrypt the result
        encrypted = encrypt(xor_result, round_keys)
        ciphertext_blocks.append(encrypted)
        
        # Update previous ciphertext
        prev_cipher = encrypted
        
    return ciphertext_blocks

def cbc_decrypt(ciphertext_blocks: list[int], key: int, iv: int) -> str:
    """
    Decrypts ciphertext blocks using S-AES in CBC mode.
    
    Args:
        ciphertext_blocks: List of ciphertext blocks (as 16-bit integers)
        key: 16-bit decryption key
        iv: 16-bit initialization vector
        
    Returns:
        Decrypted plaintext string (UTF-8)
    """
    round_keys = key_expansion(key)
    plaintext_blocks = []
    prev_cipher = iv
    
    for ciphertext_block in ciphertext_blocks:
        # Decrypt the current block
        decrypted = decrypt(ciphertext_block, round_keys)
        
        # XOR with previous ciphertext (or IV for first block)
        plaintext_block = decrypted ^ prev_cipher
        plaintext_blocks.append(plaintext_block)
        
        # Update previous ciphertext
        prev_cipher = ciphertext_block
        
    return blocks_to_text(plaintext_blocks)