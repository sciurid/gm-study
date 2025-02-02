from .mac import uint128_to_bytes, bytes_to_uint128, ZEROS_128, ghash
from .calculation import uint_incr
from typing import Tuple, Optional


def _gctr(ciph, key, icb, message) -> bytes:
    lm = len(message)
    if lm == 0:
        return b''
    n = ((lm - 1) // 16) + 1

    message = message if isinstance(message, memoryview) else memoryview(message)

    cb = bytearray(icb)
    begin = 0
    end = 16
    buffer = bytearray()
    for _ in range(n - 1):
        ek_cb = ciph(key, cb)
        block = uint128_to_bytes(bytes_to_uint128(ek_cb) ^ bytes_to_uint128(message[begin:end]))
        buffer.extend(block)
        begin = end
        end = begin + 16
        uint_incr(cb)

    padding = end - lm
    last = bytearray(message[begin:])
    last.extend(b'\x00' * padding)
    ek_cb = ciph(key, cb)
    block = uint128_to_bytes(bytes_to_uint128(ek_cb) ^ bytes_to_uint128(last))[0: lm-begin]
    buffer.extend(block)
    return bytes(buffer)


def _gcm_cipher(cipher, cipher_key, iv, message):
    key_h = cipher(cipher_key, ZEROS_128)
    if len(iv) == 12:
        j0 = iv + b'\x00\x00\x00\x01'
    else:
        j0 = uint128_to_bytes(ghash(key_h=key_h, w=b'', z=iv))
    icb = bytearray(j0)
    uint_incr(icb)
    return key_h, j0, _gctr(cipher, cipher_key, icb, message)


def gcm_encrypt(ciph, key, message, iv, auth_data) -> Tuple[bytes, bytes]:
    key_h, j0, c = _gcm_cipher(ciph, key, iv, message)
    s = uint128_to_bytes(ghash(key_h, auth_data, c))
    t = _gctr(ciph, key, j0, s)
    return c, t


def gcm_decrypt(ciph, key, iv, auth_data, cipher_text, auth_tag) -> Optional[bytes]:
    key_h, j0, p = _gcm_cipher(ciph, key, iv, cipher_text)
    s = uint128_to_bytes(ghash(key_h, auth_data, cipher_text))
    t = _gctr(ciph, key, j0, s)
    if auth_tag == t:
        return p
    else:
        return None