from typing import *
import logging

from .padding import *
from .mode import *
from .mac import gmac
from .calculation import rls_32

logger = logging.getLogger(__name__)

# GB/T 32907-2016 6.2 表1
_SM4_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c,
    0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86,
    0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed,
    0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c,
    0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb,
    0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25,
    0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38,
    0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34,
    0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82,
    0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf,
    0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1,
    0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89,
    0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39,
    0x48,
]

# GB/T 32907-2016 7.3 密钥扩展算法 b) 系统参数FK
_SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

# GB/T 32907-2016 7.3 密钥扩展算法 c) 固定参数CK
_SM4_CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]


def sm4_encrypt_block(secret_key: Union[bytes, bytearray, memoryview],
                      message: Union[bytes, bytearray, memoryview]) -> bytes:
    """SM4加密函数

    适用于一次性加密的情况，相同密钥反复使用的情况适合使用SM4类
    GB/T 32907-2016 7.1 加密算法
    :param secret_key 加密密钥
    :param message 明文消息值
    :return: 密文消息值
    """
    return SM4(secret_key).encrypt_block(message)


def sm4_decrypt_block(secret_key: Union[bytes, bytearray, memoryview],
                      cipher_text: Union[bytes, bytearray, memoryview]) -> bytes:
    """SM4解密函数

    适用于一次性解密的情况，相同密钥反复使用的情况适合使用SM4类
    :param secret_key 加密密钥
    :param cipher_text 密文消息值
    :return: 明文消息值
    """
    return SM4(secret_key).decrypt_block(cipher_text)


class SM4(BlockCipherAlgorithm):
    """SM4加解密类，适用于相同密钥反复使用的情况"""
    def __init__(self, secret_key: bytes):
        super().__init__(SM4.BLOCK_SIZE)
        self._secret_key = secret_key
        self._rks = SM4._expand_round_keys(self._secret_key)

    BLOCK_SIZE = 128

    @property
    def block_size(self) -> int:
        return self.BLOCK_SIZE

    def encrypt_block(self, message: Union[bytes, bytearray, memoryview]) -> bytes:
        return self._do_sm4_rounds(message, True)

    def decrypt_block(self, message: Union[bytes, bytearray, memoryview]) -> bytes:
        return self._do_sm4_rounds(message, False)

    @staticmethod
    def _expand_round_keys(mk_octets: Union[bytes, bytearray]):
        """GB/T 32907-2016 7.3 密钥扩展算法

        :param mk_octets 加密密钥，128-bit字节串
        """
        assert len(mk_octets) == 16
        mv = memoryview(mk_octets)
        mk = [int.from_bytes(mv[i: i + 4], byteorder='big', signed=False) for i in range(0, 16, 4)]  # 转换成4个32位整数
        for i in range(4):  # 式（6）
            mk[i] ^= _SM4_FK[i]

        def _rk(_k0, _k1, _k2, _k3, ck):
            a = _k1 ^ _k2 ^ _k3 ^ ck
            # GB/T 32907-2016 6.2 合成置换T a) 非线性变换tau
            b = 0
            for i in range(4):  # 将32位的块分成4个8位整数，经Sbox转换后重新组合成32位整数
                n = a & 0xff
                b |= _SM4_SBOX[n] << (i * 8)
                a >>= 8
            # b = _i8l_to_i32([_SM4_SBOX[n] for n in _i32_to_i8l(a)])
            c = b ^ rls_32(b, 13) ^ rls_32(b, 23)  # b) 线性变换L'
            return _k0 ^ c

        ks = [0] * 32
        for j in range(4):
            k0 = mk[j]
            k1 = mk[j + 1] if j < 3 else ks[j - 3]
            k2 = mk[j + 2] if j < 2 else ks[j - 2]
            k3 = mk[j + 3] if j < 1 else ks[j - 1]
            ks[j] = _rk(k0, k1, k2, k3, _SM4_CK[j])

        for j in range(4, 32):
            ks[j] = _rk(ks[j - 4], ks[j - 3], ks[j - 2], ks[j - 1], _SM4_CK[j])

        return ks

    def _do_sm4_rounds(self, message: Union[bytes, bytearray, memoryview], encrypt: bool = True) -> bytes:
        """SM4轮函数迭代

        GB/T 32907-2016 7.1 加密算法
        :param message 明文输入
        :param encrypt 加密/解密，True表示加密，False表示解密
        """
        if not isinstance(message, memoryview):
            message = memoryview(message)
        xs = [0] * 36
        for i, j in enumerate(range(0, 16, 4)):
            xs[i] = int.from_bytes(message[j: j + 4], byteorder='big', signed=False)

        def _round_function(x: List[int], rk: int):
            """GB/T 32907-2016 6.1 轮函数结构

            :param x 本轮输入，4个32位无符号整数
            :param rk 轮密钥，32位无符号整数
            :return 本轮输出，32为无符号整数
            """
            assert len(x) == 4
            a = x[1] ^ x[2] ^ x[3] ^ rk
            # GB/T 32907-2016 6.2 合成置换T a) 非线性变换tau
            b = 0
            for i in range(4):  # 将32位的块分成4个8位整数，经Sbox转换后重新组合成32位整数
                n = a & 0xff
                b |= _SM4_SBOX[n] << (i * 8)
                a >>= 8
            # GB/T 32907-2016 6.2 合成置换T b) 线性变换L
            c = b ^ rls_32(b, 2) ^ rls_32(b, 10) ^ rls_32(b, 18) ^ rls_32(b, 24)
            return x[0] ^ c

        for i, k in enumerate(self._rks if encrypt else reversed(self._rks)): # 加密时正向使用轮密钥，解密时反向使用轮密钥
            j = i + 4
            xs[j] = _round_function(xs[i:j], k)

        buffer = bytearray()
        for i in range(35, 31, -1):
            buffer.extend(xs[i].to_bytes(length=4, byteorder='big', signed=False))
        return bytes(buffer)


class SM4Encryptor(Codec):
    def __init__(self, secret_key: bytes, mode: str, padding: Optional[str], **kwargs):
        self.padding = get_padding(padding, SM4.BLOCK_SIZE, True)
        self.sm4 = SM4(secret_key)
        self.mode = get_mode(mode, self.sm4, **kwargs)
        self.encryptor = self.mode.encryptor()

    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        if self.padding:
            in_octets = self.padding.update(octets)
        else:
            in_octets = octets

        return self.encryptor.update(in_octets)

    def finalize(self) -> bytes:
        out_octets = bytearray()
        if self.padding:
            in_octets = self.padding.finalize()
            if len(in_octets) > 0:
                out_octets.extend(self.encryptor.update(in_octets))
        out_octets.extend(self.encryptor.finalize())
        return bytes(out_octets)


class SM4Decryptor(Codec):
    def __init__(self, secret_key: bytes, mode: str, padding: Optional[str], **kwargs):
        self.sm4 = SM4(secret_key)
        self.block_byte_len = self.sm4.block_size // 8
        self.padding = get_padding(padding, self.sm4.block_size, False)
        self.mode = get_mode(mode, self.sm4, **kwargs)
        self.decryptor = self.mode.decryptor()

    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        out_octets = bytearray()
        decrypted = self.decryptor.update(octets)
        if self.padding:
            out_octets.extend(self.padding.update(decrypted))
        else:
            out_octets.extend(decrypted)
        return bytes(out_octets)

    def finalize(self) -> bytes:
        decrypted = self.decryptor.finalize()
        if self.padding:
            return self.padding.update(decrypted) + self.padding.finalize()
        else:
            return bytes(decrypted)

def sm4_gmac(key: Union[bytes, bytearray, memoryview],
             message: Union[bytes, bytearray, memoryview], n: Union[bytes, bytearray, memoryview]) -> bytes:
    return gmac(sm4_encrypt_block, key, message, n)
