
# S-box and inverse S-box
sbox = [0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7]

inv_sbox = [0] * 16
for i in range(16):
    inv_sbox[sbox[i]] = i


def gf_mult(a, b):
    result = 0
    for _ in range(4):  # max 4 bits in GF(2^4)
        if b & 1:
            result ^= a
        carry = a & 0x8  # check highest bit (x^3)
        a <<= 1
        if carry:
            a ^= 0b10011  # irreducible polynomial: x^4 + x + 1
        a &= 0xF  # reduce to 4 bits
        b >>= 1
    return result


def int_to_state(val):  # 16-bit to 4 nibbles (column-major)
    return [(val >> 12) & 0xF,
            (val >> 8) & 0xF,
            (val >> 4) & 0xF,
            val & 0xF]

def state_to_int(state):  # 4 nibbles to 16-bit
    return (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]

def add_round_key(state, key):
    return [s ^ k for s, k in zip(state, int_to_state(key))]

def sub_nibbles(state):
    return [sbox[n] for n in state]

def inv_sub_nibbles(state):
    return [inv_sbox[n] for n in state]

def shift_rows(state):
    return [state[0], state[1], state[3], state[2]]

def mix_columns(state):
    s0, s1, s2, s3 = state
    return [
        gf_mult(1, s0) ^ gf_mult(4, s2),
        gf_mult(1, s1) ^ gf_mult(4, s3),
        gf_mult(4, s0) ^ gf_mult(1, s2),
        gf_mult(4, s1) ^ gf_mult(1, s3),
    ]


def inv_mix_columns(state):
    s0, s1, s2, s3 = state
    return [
        gf_mult(9, s0) ^ gf_mult(2, s2),
        gf_mult(9, s1) ^ gf_mult(2, s3),
        gf_mult(2, s0) ^ gf_mult(9, s2),
        gf_mult(2, s1) ^ gf_mult(9, s3)
    ]

def split_block(block):
    return [(block >> 12) & 0xF, (block >> 8) & 0xF, (block >> 4) & 0xF, block & 0xF]

def add_round_key(state, key):
    return [s ^ k for s, k in zip(state, split_block(key))]


def rotate_nibble(byte):
    # Swap high nibble and low nibble
    return ((byte << 4) & 0xF0) | ((byte >> 4) & 0x0F)

def g(byte):
    rotated = rotate_nibble(byte)
    high_nibble = sbox[(rotated >> 4) & 0xF]
    low_nibble = sbox[rotated & 0xF]
    return (high_nibble << 4) | low_nibble

def key_expansion(key):
    w = [0]*6
    w[0] = (key >> 8) & 0xFF
    w[1] = key & 0xFF
    w[2] = w[0] ^ g(w[1]) ^ 0x80  # round constant for first round
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ g(w[3]) ^ 0x30  # round constant for second round
    w[5] = w[4] ^ w[3]

    k0 = (w[0] << 8) | w[1]
    k1 = (w[2] << 8) | w[3]
    k2 = (w[4] << 8) | w[5]
    return [k0, k1, k2]


def encrypt(plaintext, key):
    print(f"Plaintext: 0x{plaintext:04X}")
    print(f"Key: 0x{key:04X}")

    # Key expansion
    round_keys = key_expansion(key)
    print(f"Round keys: {[f'0x{k:04X}' for k in round_keys]}")

    # Initial state
    state = int_to_state(plaintext)
    print(f"Initial state: {state}")

    # Round 0 - AddRoundKey
    state = add_round_key(state, round_keys[0])
    print(f"After AddRoundKey (Round 0): {state}")

    # Round 1
    state = sub_nibbles(state)
    print(f"After SubNibbles (Round 1): {state}")

    state = shift_rows(state)
    print(f"After ShiftRows (Round 1): {state}")

    state = mix_columns(state)
    print(f"After MixColumns (Round 1): {state}")

    state = add_round_key(state, round_keys[1])
    print(f"After AddRoundKey (Round 1): {state}")

    # Round 2 (final round)
    state = sub_nibbles(state)
    print(f"After SubNibbles (Round 2): {state}")

    state = shift_rows(state)
    print(f"After ShiftRows (Round 2): {state}")

    state = add_round_key(state, round_keys[2])
    print(f"After AddRoundKey (Round 2): {state}")

    ciphertext = state_to_int(state)
    print(f"Ciphertext: 0x{ciphertext:04X}")
    return ciphertext


def decrypt(ciphertext, key):
    # Convert ciphertext to state (4 nibbles)
    state = int_to_state(ciphertext)
    print(f"Initial ciphertext state: {state}")

    round_keys = key_expansion(key)
    print(f"Round keys: {[f'0x{k:04X}' for k in round_keys]}")

    # Round 2
    state = add_round_key(state, round_keys[2])
    print(f"After AddRoundKey (Round 2): {state}")

    state = shift_rows(state)
    print(f"After InvShiftRows (Round 2): {state}")

    state = inv_sub_nibbles(state)
    print(f"After InvSubNibbles (Round 2): {state}")

    # Round 1
    state = add_round_key(state, round_keys[1])
    print(f"After AddRoundKey (Round 1): {state}")

    state = inv_mix_columns(state)
    print(f"After InvMixColumns (Round 1): {state}")

    state = shift_rows(state)
    print(f"After InvShiftRows (Round 1): {state}")

    state = inv_sub_nibbles(state)
    print(f"After InvSubNibbles (Round 1): {state}")

    # Final AddRoundKey (Round 0)
    state = add_round_key(state, round_keys[0])
    print(f"After AddRoundKey (Round 0): {state}")

    # Convert back to 16-bit integer
    plaintext = state_to_int(state)
    print(f"Decrypted plaintext: 0x{plaintext:04X}")
    return plaintext