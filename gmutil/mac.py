from typing import Callable, Union
from .calculation import mul_gf_2_128
from .sm3 import sm3_hash
from .sm4 import sm4_encrypt_block

IPAD_512 = int.from_bytes(b'\x36' * 64, byteorder='big', signed=False)
OPAD_512 = int.from_bytes(b'\x5C' * 64, byteorder='big', signed=False)

def hmac(hash_function: Callable[[Union[bytes, bytearray, memoryview]], bytes], hash_block_byte_length: int,
         key: Union[bytes, bytearray, memoryview], message: Union[bytes, bytearray, memoryview]) -> bytes:
    """计算HMAC的函数

    :param hash_function: 哈希/杂凑函数
    :param hash_block_byte_length: 哈希/杂凑函数的轮函数（压缩函数）处理块长度（按字节），SM3为64字节，即SM3_BLOCk_BYTE_LENGTH
    :param key: 验证密钥，不应短于哈希/杂凑函数的输出长度（SM3为32字节）
    :param message: 要生成验证码的消息值
    :return: HMAC验证码
    """
    buffer = bytearray()
    if len(key) > hash_block_byte_length:
        buffer.extend(hash_function(key))
    else:
        buffer.extend(key)

    if len(buffer) < hash_block_byte_length:
        buffer.extend(b'\x00' * (hash_block_byte_length - len(buffer)))

    if hash_block_byte_length == 64:
        ipad = IPAD_512
        opad = OPAD_512
    else:
        ipad = int.from_bytes(b'\x36' * hash_block_byte_length, byteorder='big', signed=False)
        opad = int.from_bytes(b'\x5C' * hash_block_byte_length, byteorder='big', signed=False)

    key1 = int.from_bytes(buffer, byteorder='big', signed=False) ^ ipad
    key2 = int.from_bytes(buffer, byteorder='big', signed=False) ^ opad

    buffer.clear()
    buffer.extend(key1.to_bytes(length=hash_block_byte_length, byteorder='big', signed=False))
    buffer.extend(message)
    intermediate_hash = hash_function(buffer)
    buffer.clear()
    buffer.extend(key2.to_bytes(length=hash_block_byte_length, byteorder='big', signed=False))
    buffer.extend(intermediate_hash)
    return hash_function(buffer)


def hmac_sm3(key: Union[bytes, bytearray, memoryview], message: Union[bytes, bytearray, memoryview]):
    return hmac(sm3_hash, 64, key, message)


def uint16_to_bytes(n: int) -> bytes:
    """16字节无符号整数转化为字节串"""
    return n.to_bytes(length=16, byteorder='big', signed=False)


def bytes_to_uint16(b: bytes) -> int:
    """字节串转化为16字节无符号整数"""
    assert len(b) <= 16
    return int.from_bytes(b, byteorder='big', signed=False)


def ghash(key_h: Union[bytes, bytearray, memoryview],
          w: Union[bytes, bytearray, memoryview],
          z: Union[bytes, bytearray, memoryview]) -> int:
    """辅助函数GHASH

    GB/T 15852.3-2019 6.5.3
    :param key_h: 长度为128bit的分组H（密钥）
    :param w: 任意长度的比特串W
    :param z: 任意长度的比特串Z
    """
    assert len(key_h) == 16
    h = bytes_to_uint16(key_h)

    wm = w if isinstance(w, memoryview) else memoryview(w)
    zm = z if isinstance(z, memoryview) else memoryview(z)

    def _split_pad(s):
        l = len(s)
        blocks = []
        for i in range(0, l, 16):
            blocks.append(int.from_bytes(s[i: i + 16], byteorder='big', signed=False))
        if l % 16 != 0:
            blocks.append(int.from_bytes(s[(l % 16) - l:], byteorder='big', signed=False) << (8 * l % 16))
        return blocks

    ws = _split_pad(wm)
    zs = _split_pad(zm)

    x = 0
    for i in range(0, len(ws)):
        x = mul_gf_2_128(x ^ ws[i], h)
    for i in range(0, len(zs)):
        x = mul_gf_2_128(x ^ zs[i], h)
    last_block = ((len(w) * 8) << 64) | (len(z) * 8)
    x = mul_gf_2_128(x ^ last_block, h)

    return x


def gmac(block_cipher_encrypt: Callable[[Union[bytes, bytearray, memoryview], Union[bytes, bytearray, memoryview]], bytes],
         key: Union[bytes, bytearray, memoryview],
         message: Union[bytes, bytearray, memoryview], n: Union[bytes, bytearray, memoryview]) -> bytes:
    """计算GMAC的函数

    GB/T 15852.3-2019 6.5
    :param block_cipher_encrypt: 128bit分组加密算法函数，参数分别为消息值和密钥
    :param key: 验证密钥
    :param message: 要生成验证码的消息值
    :param n: 发送方和接收方约定的临时值
    """
    key_h = block_cipher_encrypt(b'\x00' * 16, key)
    h = ghash(key_h, message, b'')
    y_0 = (n + b'\x00' * 3 + b'\x01') if len(n) == 12 else ghash(key_h, b'', n)
    enc_y0 = block_cipher_encrypt(y_0, key)
    mac = h ^ bytes_to_uint16(enc_y0)
    return uint16_to_bytes(mac)


def gmac_sm4(key: Union[bytes, bytearray, memoryview],
         message: Union[bytes, bytearray, memoryview], n: Union[bytes, bytearray, memoryview]) -> bytes:
    return gmac(sm4_encrypt_block, key, message, n)