from s_aes import decrypt, encrypt, key_expansion


pt = 0x1234
k = 0x5678

ct = encrypt(pt,k)

decrypt(ct,k)