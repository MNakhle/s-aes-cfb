"""
utils.py

This module provides utility functions for conversions between integers,
nibbles (4-bit chunks), and hexadecimal representations. These utilities
are used throughout the simplified AES implementation.
"""

def int_to_state(val):
    """
    Convert a 16-bit integer into a list of 4 nibbles (4-bit integers).
    The output is column-major order.

    Args:
        val (int): 16-bit integer (0x0000 to 0xFFFF).

    Returns:
        List[int]: List of four 4-bit integers (nibbles).
    """
    return [(val >> 12) & 0xF,
            (val >> 8) & 0xF,
            (val >> 4) & 0xF,
            val & 0xF]

def state_to_int(state):
    """
    Convert a list of 4 nibbles into a 16-bit integer.

    Args:
        state (List[int]): List of four 4-bit integers (nibbles).

    Returns:
        int: 16-bit integer representation.
    """
    return (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]

def rotate_nibble(byte):
    """
    Swap the high nibble and the low nibble of a byte.

    Args:
        byte (int): 8-bit integer.

    Returns:
        int: Byte with nibbles swapped.
    """
    return ((byte << 4) & 0xF0) | ((byte >> 4) & 0x0F)

def split_block(block):
    """
    Split a 16-bit block into a list of four nibbles.

    Args:
        block (int): 16-bit integer.

    Returns:
        List[int]: List of four nibbles.
    """
    return [(block >> 12) & 0xF, (block >> 8) & 0xF, (block >> 4) & 0xF, block & 0xF]
