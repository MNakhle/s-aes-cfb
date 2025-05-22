# 🔐 Simple AES CFB Mode Cipher & Cryptanalysis Tool

This project implements a basic **AES CFB (Cipher Feedback) mode** encryption system and provides tools to analyze and break ciphertexts using frequency analysis, brute force, and known-plaintext attacks.

---

## 🚀 Features

- 🔒 Encrypt plaintext using a simple stream cipher in CFB mode.
- 🔓 Decrypt ciphertext with the correct key and IV.
- 🕵️‍♂️ Smart `Cryptanalyst` class with:
  - Frequency analysis
  - Brute-force attack with common plaintexts
  - Interactive known-plaintext attack from user input
- 📈 Clear precision scores for evaluating decryption candidates

---

## 🧪 Demo Output

```text
PlainText       : Okay you got me
Ciphertext (hex): e33f0304ca78373798eabe7c647ef092
Decrypted Text  : Okay you got me

------------Cryptanalysis------------


Attempting frequency analysis...

(note frequency analysis has levels of accuracy you must read decrypted text and determin for your self if it is correct)

Key: 0x1a2b 
percision: 0.06333333333333332 
decryption: okay you got me 
---------------------------
Key: 0xe156 
percision: 0.02357142857142857 
decryption: <2,r滊btepe, 
---------------------------
...

starting brute force for common text
(estimated time: ~3.5 seconds)


Brute-force failed. Would you like to try your own plaintext guess?
Enter a known plaintext (or press ENTER to skip): okay
No key found with that plaintext. Try another one.

Brute-force failed. Would you like to try your own plaintext guess?
Enter a known plaintext (or press ENTER to skip): Okay
Key recovered using user-provided plaintext: Okay

✅ Recovered key: 0x1a2b
🔓 Decrypted message: Okay you got me
```

## 🧠 How It Works

This project demonstrates the implementation and cryptanalysis of the Simplified Advanced Encryption Standard (S-AES) operating in Cipher Feedback (CFB) mode.

- <b>Block Cipher Operations:</b> S-AES performs a series of substitutions (SubNib), shifts (ShiftRow), and mixings   (MixColumn), combined with key addition (AddRoundKey), over 16-bit blocks of data.
- <b>Cipher Feedback (CFB) Mode:</b> We utilize S-AES in CFB mode, transforming the block cipher into a stream-like cipher.
    1. <b>Encryption:</b> Instead of directly encrypting plaintext blocks, CFB encrypts the Initialization Vector (IV) or the previous ciphertext block. The output of this encryption is then XORed with the current plaintext block to produce the ciphertext. This means that an error in one ciphertext block will propagate to subsequent blocks.
    2. <b>Decryption:</b> The decryption process mirrors encryption, using the same S-AES encryption function on the IV or previous ciphertext block, and XORing the result with the current ciphertext to recover the plaintext. This allows for self-synchronization.

## 🕵️‍♀️ Cryptanalysis Workflow: Deciphering S-AES-CFB

This project explores various cryptanalytic techniques tailored to break S-AES-CFB, focusing on scenarios where partial information might be known or deduced.

- <b>Exhaustive Key Search (Brute-Force Attack):</b>

    1. <b>Strategy:</b> For a given ciphertext, IV, and a fragment of known plaintext (e.g., the beginning of the message), the system iterates through every single possible 16-bit S-AES key (2^16 keys).

    2. <b>Identification:</b> Each trial key is used to decrypt the ciphertext. If the decrypted output matches the known plaintext fragment, the key is identified as the correct one. This demonstrates the feasibility of brute-force against a small key space like S-AES.
- <b>Frequency Analysis (Text-Based Attacks):</b>

    1. <b>Applicability:</b> While full S-AES is resistant to basic frequency analysis, this module explores its potential application in specific scenarios (e.g., if highly biased plaintext statistical properties or partial plaintexts could be deduced, or for pedagogical purposes).
    2. <b>Method:</b> Scores possible keys based on how "English-like" the decrypted text appears, using statistical properties of the English language. This provides top key candidates with a confidence score.

## ▶️ How to Run

```
python main.py
```
to enable interactive plaintext guessing during cryptanalysis:
```
python main.py --interactive
```

## 📦 Requirements

No external libraries are required. Uses only Python 3 standard libraries.

## ✍️ Author

Crafted with 🧠 and 🧪 by Mario Nakhle