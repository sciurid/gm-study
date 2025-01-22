import os
import secrets
import random
import logging
from gmutil import mul_gf_2_128
from gmutil import sm4_encrypt_block

logger = logging.getLogger(__name__)


def ghash(key_h: bytes, w: bytes, z: bytes) -> int:
    assert len(key_h) == 16
    h = bytes_to_uint(key_h)

    def _split_pad(s):
        l = len(s)
        blocks = []
        for i in range(0, l, 16):
            blocks.append(int.from_bytes(s[i: i + 16], byteorder='big', signed=False))
        if l % 16 != 0:
            blocks.append(int.from_bytes(s[(l % 16) - l:], byteorder='big', signed=False) << (8 * l % 16))
        return blocks

    ws = _split_pad(w)
    zs = _split_pad(z)

    x = 0
    for i in range(0, len(ws)):
        # x = mul_on_gf2_128(x ^ ws[i], h)
        x = mul_gf_2_128(x ^ ws[i], h)
    for i in range(0, len(zs)):
        # x = mul_on_gf2_128(x ^ zs[i], h)
        x = mul_gf_2_128(x ^ zs[i], h)
    # last_block = (int.to_bytes(len(w) * 8, length=8, byteorder='big', signed=False)
    #               + int.to_bytes(len(z) * 8, length=8, byteorder='big', signed=False))
    last_block = ((len(w) * 8) << 64) | (len(z) * 8)
    # x = mul_on_gf2_128(x ^ last_block, h)
    x = mul_gf_2_128(x ^ last_block, h)

    return x


def uint_to_bytes(n: int) -> bytes:
    return n.to_bytes(length=16, byteorder='big', signed=False)


def bytes_to_uint(b: bytes) -> int:
    assert len(b) <= 16
    return int.from_bytes(b, byteorder='big', signed=False)


def gmac(key: bytes, message: bytes, n: bytes) -> bytes:
    logger.debug('-' * 20 + 'GMAC' + '-' * 20)
    key_h = sm4_encrypt_block(b'\x00' * 16, key)
    h = ghash(key_h, message, b'')
    y_0 = (n + b'\x00' * 3 + b'\x01') if len(n) == 12 else ghash(key_h, b'', n)
    enc_y0 = sm4_encrypt_block(message=y_0, secret_key=key)
    mac = h ^ bytes_to_uint(enc_y0)
    return uint_to_bytes(mac)


