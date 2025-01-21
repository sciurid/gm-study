import os
import secrets
import random

from gmutil import sm4_encrypt_block

MASK_128 = (0x01 << 128) - 1



V_MASK_START = 0x01 << 127
REMAINDER = 0b11100001 << 120

def mul(u: int, v: int) -> int:
    assert u.bit_length() <= 128
    assert v.bit_length() <= 128

    w = 0
    z = u
    v_mask = V_MASK_START
    for i in range(0, 128):
        if v & v_mask != 0:
            w = w ^ z
        v_mask >>= 1

        if z & 0x01 == 0:
            z = z >> 1
        else:
            z = (z >> 1) ^ REMAINDER

    return w

def mul_on_gf2_128(u: int, v: int):
    """在GF(2^128)上的多项式乘法

    :param u: 多项式的二进制表示
    :param v: 多项式的二进制表示
    :return: u和v在GF(2^128)上的多项式乘法结果

    参见《密码编码学与网络安全：原理与实践（第八版）》P94
    """

    assert u.bit_length() <= 128
    assert v.bit_length() <= 128

    # {m(x) = x^128 + x^7 + x^2 + x + 1}
    w = 0  # sum
    z = u  # {u \mul 2^i}
    for _ in range(128):
        if v & 0x01 != 0:
            w ^= z
        v >>= 1

        if z >> 127 == 0:  # b128 !=0 时，需要模{m(x)}
            z = (z << 1)
        else:
            z = ((z << 1) ^ 0b10000111) & MASK_128
    return w

MASK_8 = ((0x01 << 8) - 1)

def mul_on_gf2_8(u: int, v: int):
    assert u.bit_length() <= 8
    assert v.bit_length() <= 8

    # {m(x) = x^8 + x^4 + x^3 + x^2 + x + 1}
    w = 0  # sum
    z = u  # {u \mul 2^i}

    # print('Z:{:08b}'.format(z))
    for _ in range(8):
        # print(_)
        # print('V:{:08b}'.format(v))
        if v & 0x01 != 0:
            w ^= z
        # print('W:{:08b}'.format(w))
        v >>= 1


        if z >> 7 == 0:  # b8 !=0 时，需要模{m(x)}
            z = (z << 1)
        else:
            z = ((z << 1) ^ 0b00011101) & MASK_8
        # print('Z:{:08b}'.format(z))
    return w


def ghash(h: int, w: bytes, z: bytes) -> int:
    assert h.bit_length() <= 128

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
        x = mul(x ^ ws[i], h)
    for i in range(0, len(zs)):
        # x = mul_on_gf2_128(x ^ zs[i], h)
        x = mul(x ^ zs[i], h)
    # last_block = (int.to_bytes(len(w) * 8, length=8, byteorder='big', signed=False)
    #               + int.to_bytes(len(z) * 8, length=8, byteorder='big', signed=False))
    last_block = ((len(w) * 8) << 64) | (len(z) * 8)
    # x = mul_on_gf2_128(x ^ last_block, h)
    x = mul(x ^ last_block, h)

    return x


def uint_to_bytes(n: int) -> bytes:
    return n.to_bytes(length=16, byteorder='big', signed=False)

def bytes_to_uint(b: bytes) -> int:
    assert len(b) <= 16
    return int.from_bytes(b, byteorder='big', signed=False)



from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



def gcm(key, message, n ):
    print("-" * 60)
    print("Key:", key.hex())
    print("KHV:", '00' * 16)
    key_h = sm4_encrypt_block(b'\x00' * 16, key)
    key_h_int = bytes_to_uint(key_h)
    print("Key_H:", key_h.hex())
    h = ghash(key_h_int, message, b'')
    print("H:", uint_to_bytes(h).hex())
    y_0 = (n + b'\x00' * 3 + b'\x01') if len(n) == 12 else ghash(key_h_int, b'', n)
    print("Y0:", y_0.hex())

    enc_y0 = sm4_encrypt_block(message=y_0, secret_key=key)
    print("ENC Y0:", enc_y0.hex(' '))

    mac = h ^ bytes_to_uint(enc_y0)
    print("MAC:", uint_to_bytes(mac).hex(' '))
    return uint_to_bytes(mac)


gcm(b'\x00' * 16, b'', b'\x00' * 12)
mine = gcm(
    key = bytes.fromhex('fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08'),
    message=bytes.fromhex('fe ed fa ce de ad be ef fe ed fa ce de ad be ef'),
    n = bytes.fromhex('ca fe ba be fa ce db ad de ca f8 88')
)

ref = bytes.fromhex('9d 63 25 70 f9 30 64 26 4a 20 91 8e 30 81 b4 cd')
assert mine == ref












# u = secrets.randbits(8)
#
# for i in range(128):
#     v1 = secrets.randbits(8)
#     v2 = 2 # secrets.randbits(128)
#     r11 = mul_on_gf2_8(u, v1)
#     r12 = mul_on_gf2_8(v1, u)
#     r21 = mul_on_gf2_8(u, v2)
#     r22 = mul_on_gf2_8(v2, u)
#     r3 = mul_on_gf2_8(u, v1 ^ v2)
#
#     assert r11 == r12
#     assert r21 == r22
#     assert r3 == (r11 ^ r21) == (r12 ^ r22)

u = secrets.randbits(128)

for i in range(128):
    v1 = secrets.randbits(128)
    v2 = secrets.randbits(128)
    r11 = mul_on_gf2_128(u, v1)
    r12 = mul_on_gf2_128(v1, u)
    r21 = mul_on_gf2_128(u, v2)
    r22 = mul_on_gf2_128(v2, u)
    r3 = mul_on_gf2_128(u, v1 ^ v2)

    assert r11 == r12
    assert r21 == r22
    assert r3 == (r11 ^ r21) == (r12 ^ r22)











