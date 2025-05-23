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


def text_to_blocks(text):
    """
    Converts a UTF-8 encoded string into a list of 16-bit integer blocks.

    Each block consists of two bytes from the input string, combined into a single
    16-bit integer. If the string has an odd number of bytes, the final block is
    padded with a trailing zero byte.

    Args:
        text (str): The input string to be converted.

    Returns:
        List[int]: A list of 16-bit integer blocks representing the input string.
    """
    byte_array = text.encode('utf-8')
    blocks = []
    for i in range(0, len(byte_array), 2):
        if i + 1 < len(byte_array):
            block = (byte_array[i] << 8) | byte_array[i+1]
        else:
            block = (byte_array[i] << 8)  # pad last block with 0
        blocks.append(block)
    return blocks


def blocks_to_text(blocks, force_text=False):
    """
    Converts a list of 16-bit integer blocks back into the original UTF-8 string.

    Each 16-bit block is split into two bytes. If the original string was padded 
    during block formation, the trailing null byte is removed before decoding.

    Args:
        blocks (List[int]): A list of 16-bit integer blocks.

    Returns:
        str: The reconstructed string from the given blocks.
    """
    bytes_out = bytearray()
    for block in blocks:
        bytes_out.append((block >> 8) & 0xFF)
        bytes_out.append(block & 0xFF)
    
    # Remove padding while preserving possible binary data
    clean_bytes = bytes_out.rstrip(b'\x00')
    
    try:
        return clean_bytes.decode('utf-8')
    except UnicodeDecodeError:
        if force_text:
            raise
        return clean_bytes 


def blocks_to_hex_string(blocks: list[int]) -> str:
    """
    Converts a list of 16-bit integer blocks (e.g., from S-AES ciphertext)
    into a continuous hexadecimal string.

    This function is useful for representing binary ciphertext in a
    human-readable, text-safe format for sharing or display.

    Args:
        blocks: A list of integers, where each integer represents a 16-bit block.

    Returns:
        A string containing the hexadecimal representation of all the blocks,
        concatenated together. Each 16-bit block will be represented by 4 hex characters.

    Example:
        >>> blocks_to_hex_string([0x1234, 0xABCD])
        '1234abcd'
    """
    bytes_out = bytearray()
    # Iterate through each 16-bit integer block in the input list
    for block in blocks:
        # Extract the Most Significant Byte (MSB)
        # Shift the 16-bit block 8 bits to the right (>> 8) to move the MSB to the
        # least significant byte position.
        # Then, apply a bitwise AND with 0xFF (11111111 in binary) to mask off
        # any remaining higher bits, ensuring we only get the 8-bit MSB.
        bytes_out.append((block >> 8) & 0xFF)  # Most significant byte (MSB)

        # Extract the Least Significant Byte (LSB)
        # Apply a bitwise AND with 0xFF to isolate the lower 8 bits.
        # This effectively gets the LSB of the 16-bit block.
        bytes_out.append(block & 0xFF)        # Least significant byte (LSB)

    # Convert the collected bytearray to a hexadecimal string
    # The .hex() method on a bytes or bytearray object efficiently converts
    # its binary content into a string where each byte is represented by two
    # hexadecimal characters (e.g., b'\x01\x0A' becomes '010a').
    return bytes_out.hex()


def hex_to_blocks(hex_string: str) -> list[int]:
    """
    Converts a hexadecimal string representing ciphertext into a list of 16-bit integer blocks.

    Args:
        hex_string: The hexadecimal string (e.g., '1234ABCD').
                    It must have an even number of characters.

    Returns:
        A list of 16-bit integers, where each integer represents a block.

    Raises:
        ValueError: If the hex_string has an odd number of characters.
    """
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have an even number of characters.")

    # Convert the hex string to a bytes object
    # This will result in a bytes object like b'\x12\x34\xAB\xCD'
    raw_bytes = bytes.fromhex(hex_string)

    blocks = []
    # Iterate over the bytes in pairs (each pair forms a 16-bit block)
    for i in range(0, len(raw_bytes), 2):
        # Combine two bytes into a 16-bit integer
        # (byte1 << 8) shifts the first byte 8 bits to the left, making it the MSB
        # | (bitwise OR) combines it with the second byte (LSB)
        block = (raw_bytes[i] << 8) | raw_bytes[i+1]
        blocks.append(block)

    return blocks