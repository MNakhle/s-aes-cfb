from crypt_analysis.Cryptanalyst import Cryptanalyst
from s_aes import cfb_encrypt, cfb_decrypt, blocks_to_text, text_to_blocks
from s_aes.utils import blocks_to_hex_string

def main():
    key = 0x1A2B
    iv = 0xAAAA
    plaintext = "Okay you got me"
    print(f"PlainText: {plaintext}")

    # Encrypt
    ciphertext_blocks = cfb_encrypt(plaintext, key, iv)
    print(f"cypher_hex : {blocks_to_hex_string(ciphertext_blocks)}")

    # Decrypt
    decrypted_text = cfb_decrypt(ciphertext_blocks, key, iv)
    print(f"decrypted_text: {decrypted_text}")

    #-------------------------------------------Cryptanalysis------------------------------------------------- 
    print("\n------------Cryptanalysis------------\n")   

    analyst = Cryptanalyst(decrypt_fn=cfb_decrypt, block_size=8)

    # Try to recover the key
    recovered_key = analyst.optimized_attack(ciphertext_blocks,iv)

    if recovered_key is not None:
        print(f"Recovered key: {hex(recovered_key)}")
        decrypted = cfb_decrypt(ciphertext_blocks, recovered_key,iv)
        print(f"Decrypted message: {decrypted}")
    else:
        print("Failed to recover key.")


if __name__ == "__main__":
    main()
