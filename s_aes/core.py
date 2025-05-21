"""
core.py

Contains the core logic for S-AES including:
- S-box and inverse S-box
- Galois Field multiplication
- State conversions
- SubBytes, ShiftRows, MixColumns
- Key expansion (round key generation)
"""

# S-box and Inverse S-box (static substitution tables)
from .utils import int_to_state,rotate_nibble


sbox = [0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7]

inv_sbox = [0] * 16
for i in range(16):
    inv_sbox[sbox[i]] = i

def gf_mult(a: int, b: int) -> int:
    """
    Perform Galois Field multiplication in GF(2^4) using the
    irreducible polynomial x^4 + x + 1 (0b10011).
    """
    result = 0
    for _ in range(4):
        if b & 1:
            result ^= a
        carry = a & 0x8
        a <<= 1
        if carry:
            a ^= 0b10011
        a &= 0xF
        b >>= 1
    return result


def add_round_key(state, key):
    """
    Performs the AddRoundKey step in S-AES.

    This step XORs the state with the round key.

    Args:
        state (list[int]): A 4-element list representing the current state matrix.
        round_key (list[int]): A 4-element list representing the round key.

    Returns:
        list[int]: The new state after XOR with the round key.
    """
    return [s ^ k for s, k in zip(state, int_to_state(key))]

def sub_nibbles(state: list) -> list:
    """Apply S-box substitution on state."""
    return [sbox[n] for n in state]

def inv_sub_nibbles(state: list) -> list:
    """Apply inverse S-box substitution on state."""
    return [inv_sbox[n] for n in state]

def shift_rows(state: list) -> list:
    """Perform ShiftRows transformation (swap last two nibbles)."""
    return [state[0], state[1], state[3], state[2]]

def mix_columns(state: list) -> list:
    """Perform MixColumns transformation using GF multiplication."""
    s0, s1, s2, s3 = state
    return [
        gf_mult(1, s0) ^ gf_mult(4, s2),
        gf_mult(1, s1) ^ gf_mult(4, s3),
        gf_mult(4, s0) ^ gf_mult(1, s2),
        gf_mult(4, s1) ^ gf_mult(1, s3)
    ]

def inv_mix_columns(state: list) -> list:
    """Perform inverse MixColumns transformation."""
    s0, s1, s2, s3 = state
    return [
        gf_mult(9, s0) ^ gf_mult(2, s2),
        gf_mult(9, s1) ^ gf_mult(2, s3),
        gf_mult(2, s0) ^ gf_mult(9, s2),
        gf_mult(2, s1) ^ gf_mult(9, s3)
    ]

def g(byte: int) -> int:
    """
    Function g used in key expansion:
    - Rotate byte
    - Substitute both nibbles using S-box
    """
    rotated = rotate_nibble(byte)
    high_nibble = sbox[(rotated >> 4) & 0xF]
    low_nibble = sbox[rotated & 0xF]
    return (high_nibble << 4) | low_nibble

def key_expansion(key: int) -> list:
    """
    Expand 16-bit key into three 16-bit round keys for S-AES.
    Returns list: [K0, K1, K2]
    """
    w = [0] * 6
    w[0] = (key >> 8) & 0xFF
    w[1] = key & 0xFF
    w[2] = w[0] ^ g(w[1]) ^ 0x80  # First round constant
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ g(w[3]) ^ 0x30  # Second round constant
    w[5] = w[4] ^ w[3]

    k0 = (w[0] << 8) | w[1]
    k1 = (w[2] << 8) | w[3]
    k2 = (w[4] << 8) | w[5]
    return [k0, k1, k2]