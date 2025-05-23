import binascii
import string
from crypt_analysis.Cryptanalyst import Cryptanalyst
from s_aes import decrypt
from s_aes.core import key_expansion


def is_mostly_printable_ascii(byte_string: bytes, threshold: float = 0.4) -> bool:
    if not byte_string:
        return False # Empty string is not "readable"

    printable_count = 0
    total_chars = len(byte_string)


    printable_chars = set(ord(c) for c in string.printable)

    for byte_val in byte_string:
        if byte_val in printable_chars:
            printable_count += 1
    
    return (printable_count / total_chars) >= threshold



def cbc_decrypt(cipher_blocks,key,iv) :
    decrypted_blocks = []
    prev = iv

    for c in cipher_blocks:
        p = xor_block(s_aes_decrypt_block(c, key), prev)
        decrypted_blocks.append(p)
        prev = c

    text = blocks_to_text(decrypted_blocks)
    if(is_mostly_printable_ascii(text)) :
        print(f"\n✅ decrypted: {text}")


    return blocks_to_text(decrypted_blocks)



# Dummy placeholder for S-AES decrypt (you'll need to implement or plug in an existing S-AES decrypt function)
def s_aes_decrypt_block(block: int, key: int) -> int:
    return decrypt(block,key_expansion(key))

def xor_block(a: int, b: int) -> int:
    return a ^ b

def hex_to_blocks(hex_str):
    return [int(hex_str[i:i+4], 16) for i in range(0, len(hex_str), 4)]

def blocks_to_text(blocks):
    return ''.join(chr((b >> 8) & 0xFF) + chr(b & 0xFF) for b in blocks)

def bruteforce_cbc(cipher_blocks, iv, known_plaintexts):
    for key in range(0x0000, 0x10000):
        decrypted_blocks = []
        prev = iv

        for c in cipher_blocks:
            p = xor_block(s_aes_decrypt_block(c, key), prev)
            decrypted_blocks.append(p)
            prev = c

        decrypted = blocks_to_text(decrypted_blocks)

        for plaintext in known_plaintexts:
            if plaintext in decrypted:
                print(f"[+] Key found: 0x{key:04x}")
                print(f"[+] Decrypted text: {plaintext}")
                return key, plaintext

    print("[-] Key not found.")
    return None, None

if __name__ == "__main__":
    # Example usage
    # Ciphertext with real IV (first 4 hex chars are IV)
    hex_input = "cdefd16e59858f0185a8bd3fbca84ff584d033688f649b49ee6c50d8691923b95031fbcf916d993d"
    
    blocks = hex_to_blocks(hex_input)
    iv = blocks[0]
    cipher_blocks = blocks[1:]

    # Optional: try a likely prefix
    known_prefix = ['Hello','hellp','i43','I43','name','cypher','cipher','Cypher','okay','the','what'] # or try None for full search

    analyst = Cryptanalyst(decrypt_fn=cbc_decrypt, block_size=8)

    # Try to recover the key
    recovered_key = analyst.optimized_attack(cipher_blocks,iv)

    # Attempt brute-force
    # bruteforce_cbc(cipher_blocks, iv, known_prefix)



        