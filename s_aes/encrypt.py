from .core import (
    sub_nibbles,
    shift_rows,
    mix_columns,
    key_expansion,
    add_round_key
)
from .utils import (
    int_to_state,
    state_to_int
)

def encrypt(plaintext: int, round_keys) -> int:
    """
    Encrypts a 16-bit plaintext using simplified AES with a 16-bit key.

    Args:
        plaintext (int): The plaintext block to encrypt (16-bit).
        key (int): The encryption key (16-bit).

    Returns:
        int: The ciphertext block (16-bit).
    """
    state = int_to_state(plaintext)

    # Initial round key addition
    state = add_round_key(state, round_keys[0])

    # Round 1
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_keys[1])

    # Round 2
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[2])

    return state_to_int(state)