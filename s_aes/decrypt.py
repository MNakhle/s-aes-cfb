from .core import (
    key_expansion,
    inv_sub_nibbles,
    add_round_key,
    inv_mix_columns,
    shift_rows
)
from .utils import (
    int_to_state,
    state_to_int,
)


def decrypt(ciphertext: int, round_keys) -> int:
    """
    Decrypts a 16-bit ciphertext using simplified AES with a 16-bit key.

    Args:
        ciphertext (int): The ciphertext block to decrypt (16-bit).
        key (int): The encryption key (16-bit).

    Returns:
        int: The decrypted plaintext block (16-bit).
    """
    state = int_to_state(ciphertext)

    # Inverse Final Round
    state = add_round_key(state, round_keys[2])
    state = shift_rows(state)
    state = inv_sub_nibbles(state)

    # Inverse Round 1
    state = add_round_key(state, round_keys[1])
    state = inv_mix_columns(state)
    state = shift_rows(state)
    state = inv_sub_nibbles(state)

    # Final round key addition
    state = add_round_key(state, round_keys[0])

    return state_to_int(state)
