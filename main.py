import string
from cbc_project.saes_cbc import s_aes_cbc_decrypt
from crypt_analysis.Cryptanalyst import Cryptanalyst
from s_aes import cfb_encrypt, cfb_decrypt, blocks_to_text, decrypt, text_to_blocks
from s_aes.cbc import cbc_decrypt, cbc_encrypt
from s_aes.core import key_expansion
from s_aes.utils import blocks_to_hex_string, hex_to_blocks


def main():
    key = 0x1A2B
    iv = 0xAAAA
    plaintext = "Okay you got me!"
    
    # Encrypt
    ciphertext_blocks = cfb_encrypt(plaintext, key, iv)

    # Decrypt
    decrypted_text = cfb_decrypt(ciphertext_blocks, key, iv)

    print(f"PlainText       : {plaintext}")
    print(f"Ciphertext (hex): {blocks_to_hex_string(ciphertext_blocks)}")
    print(f"Decrypted Text  : {decrypted_text}")

    #-------------------------------------------Cryptanalysis------------------------------------------------- 
    print("\n------------Cryptanalysis------------\n")   


    analyst = Cryptanalyst(decrypt_fn=cfb_decrypt, block_size=8)

    # Try to recover the key
    recovered_key = analyst.optimized_attack(ciphertext_blocks,iv)

    if recovered_key is not None:
        print(f"\n✅ Recovered key: {hex(recovered_key)}")
        decrypted = cfb_decrypt(ciphertext_blocks, recovered_key,iv)
        print(f"🔓 Decrypted message: {decrypted}")
    else:
        print("\n❌ Failed to recover key.")

    #----------------------------------------Cryptanalysis-Foreign----------------------------------------------

    print("\n------------Cryptanalysis-Foreign------------\n")   

    analyst = Cryptanalyst(decrypt_fn=s_aes_cbc_decrypt, block_size=8)

    cypherhex = "20bec925a282f7d79adfa09f8ad719b9cb98e39de4240b15f9e0a908fca7ee1b4a5ed739c729b0ff"
    cypher_blocks = bytes.fromhex(cypherhex)

    print(f"CypherText (hex)    : {cypherhex}")
    print(f"CypherText (blocks) : {cypher_blocks}")

    recovered_key = analyst.optimized_attack(cypher_blocks)

    if recovered_key is not None:
        print(f"\n✅ Recovered key: {hex(recovered_key)}")
        decrypted = s_aes_cbc_decrypt(cypher_blocks, recovered_key)
        print(f"🔓 Decrypted message: {decrypted}")

    else:
        print("\n❌ Failed to recover key.")


if __name__ == "__main__":
    main()
