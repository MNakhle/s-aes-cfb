"""
s_aes package

This package implements S-AES (Simplified AES) encryption and decryption
along with necessary utility functions, key expansion, and support for modes of operation like CFB.
"""

from .core import key_expansion, g, gf_mult
from .encrypt import encrypt
from .decrypt import decrypt
from .utils import (
    int_to_state, state_to_int,
    split_block, rotate_nibble,
    text_to_blocks,blocks_to_text
)
from .cfb import cfb_encrypt, cfb_decrypt

# Optional: expose submodules if needed directly
__all__ = [
    "encrypt",
    "decrypt",
    "key_expansion",
    "int_to_state",
    "state_to_int",
    "split_block",
    "rotate_nibble",
    "g",
    "gf_mult",
    "cfb_encrypt",
    "cfb_decrypt",
    "text_to_blocks",
    "blocks_to_text"
    ]