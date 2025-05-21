from s_aes import cfb_decrypt , blocks_to_text


def brute_force_cfb(ciphertext_blocks, known_plaintext, iv):
    for key in range(0x0000, 0x10000):
        try:
            decrypted_blocks = cfb_decrypt(ciphertext_blocks, key, iv)
            decrypted_text = blocks_to_text(decrypted_blocks)
            
            if known_plaintext in decrypted_text:
                print(f"[+] Key found: 0x{key:04x}")
                print(f"Decrypted text: {decrypted_text}")
                return key
        except Exception as e:
            # If your decryption crashes with a key, just skip it
            continue

    print("[-] Key not found.")
    return None
