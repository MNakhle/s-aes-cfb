from s_aes import cfb_encrypt, cfb_decrypt, blocks_to_text, text_to_blocks
from crypt_analysis.bruteforce_kpa import brute_force_cfb
from s_aes.utils import blocks_to_hex_string

def main():
    key = 0x1A2B
    iv = 0xAAAA
    plaintext = "You Got It :)"
    print(f"PlainText: {plaintext} | block form: {text_to_blocks(plaintext)}")

    # Encrypt
    ciphertext_blocks = cfb_encrypt(plaintext, key, iv)
    print(f"ciphertext_blocks : {ciphertext_blocks} | cypher_hex : {blocks_to_hex_string(ciphertext_blocks)}")

    # Decrypt
    decrypted_blocks = cfb_decrypt(ciphertext_blocks, key, iv)
    decrypted_text = blocks_to_text(decrypted_blocks)
    print(f"decrypted_text: {decrypted_text} | decrypted_blocks: {decrypted_blocks}")

#----------------------------------------------------------------------------------------

    plaintext = "Hello!"
    print(f"plaintext: {plaintext}")
    ciphertext_blocks = cfb_encrypt(plaintext, key, iv)
    print(f"ciphertext_blocks: {ciphertext_blocks}")

    # Simulate attack with ciphertext, IV, and known plaintext
    print("\nStarting brute-force...")
    brute_force_cfb(ciphertext_blocks, "Hello!", iv)


if __name__ == "__main__":
    main()
