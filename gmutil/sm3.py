from typing import Union, Tuple, Sequence
from .mac import hmac
from .calculation import rls_32, mod_adds_32

# GB/T 32905-2016 4.1 初始值
_SM3_IV = (0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e)

# GB/T 32905-2016 4.2 常量
_SM3_TJ = tuple(0x79cc4519 if 0 <= j < 16 else 0x7a879d8a for j in range(0, 64))


def _sm3_ff_j(x: int, y: int, z: int, j: int):
    """GB/T 32905-2016 4.3 布尔函数FF_j"""
    # assert x.bit_length() <= 32
    # assert y.bit_length() <= 32
    # assert z.bit_length() <= 32
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        ret = (x & y) | (x & z) | (y & z)
    else:
        raise ValueError(f"j = {j}")
    return ret


def _sm3_gg_j(x: int, y: int, z: int, j):
    """GB/T 32905-2016 4.3 布尔函数GG_j"""
    # assert x.bit_length() <= 32
    # assert y.bit_length() <= 32
    # assert z.bit_length() <= 32
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        ret = (x & y) | ((~ x) & z)
    else:
        raise ValueError(f"j = {j}")
    return ret


def _sm3_p0(x: int):
    """GB/T 32905-2016 4.4 置换函数P0"""
    # assert x.bit_length() <= 32
    return x ^ rls_32(x, 9) ^ rls_32(x, 17)


def _sm3_p1(x: int):
    """GB/T 32905-2016 4.4 置换函数P1"""
    # assert x.bit_length() <= 32
    return x ^ rls_32(x, 15) ^ rls_32(x, 23)


def sm3_hash(message: Union[bytes, bytearray, memoryview]) -> bytes:
    sm3hash = SM3Hash()
    sm3hash.update(message)
    return sm3hash.digest()


SM3_BLOCK_BYTE_LENGTH = 64
SM3_OUTPUT_BYTE_LENGTH = 32


def sm3_kdf(data: Union[bytes, bytearray, memoryview], m_len: int):
    """SM3密钥派生函数
    GB/T 32918.4-2016 6.4.3 (P3)
    data: 比特串
    m_len: 要派生出的密钥字节数
    """
    res = bytearray()
    buffer = bytearray(data)
    dbl = len(data)

    # 以SM3的输出长度（256 bits=32 bytes）分块
    # 计数器从1开始
    for ctr in range(1, (m_len - 1) // SM3Hash.DIGEST_BYTE_LENGTH + 2):
        del buffer[dbl:]
        buffer.extend(int.to_bytes(ctr + 1, length=4, byteorder='big'))
        res.extend(sm3_hash(buffer))

    return bytes(res[0:m_len])

def sm3_hmac(key: Union[bytes, bytearray, memoryview], message: Union[bytes, bytearray, memoryview]):
    return hmac(sm3_hash, 64, key, message)


class SM3Hash:
    BLOCK_BYTE_LENGTH = 64
    BLOCK_SIZE = BLOCK_BYTE_LENGTH * 8
    DIGEST_BYTE_LENGTH = 32
    DIGEST_SIZE = DIGEST_BYTE_LENGTH * 8

    def __init__(self, buffer_limit: int = 1024):
        self._buffer = bytearray()
        self._cursor = 0
        self._offset = 0
        self._v = list(_SM3_IV)

        self._w = [0] * 68
        self._w_ = [0] * 64

        self._buffer_limit = buffer_limit

    def _expand(self, block_in: memoryview):
        """消息扩展函数

        GB/T 32905-2016 5.3.2
        :param block_in: 输入的64字节消息
        :return: 返回的w和w'，分别为68个32bit整数和64个32bit整数，用于CF压缩函数
        """
        # assert len(block_in) == 64
        w = self._w
        j, m, n = 0, 0, 4
        while j < 16:
            w[j] = int.from_bytes(block_in[m:n], byteorder='big', signed=False)
            j += 1
            m = n
            n = m + 4

        # w = [int.from_bytes(block_in[i:i + 4], byteorder='big', signed=False) for i in range(0, len(block_in), 4)]
        for j in range(16, 68):
            w[j] = _sm3_p1(w[j - 16] ^ w[j - 9] ^ rls_32(w[j - 3], 15)) ^ rls_32(w[j - 13], 7) ^ w[j - 6]

        w_ = self._w_
        for j in range(0, 64):
            w_[j] = w[j] ^ w[j + 4]

    def _cf(self, block_in: memoryview):
        """CF压缩函数：GB/T 32905-2016 5.3.3

        v_i: 迭代压缩输入32 bytes（256 bits）
        b_i: 消息分组输入32 bytes（256 bits）
        """
        # assert len(block_in) == 64

        self._expand(block_in)

        a, b, c, d, e, f, g, h = self._v
        for j in range(0, 64):
            ss1 = rls_32(
                mod_adds_32(rls_32(a, 12), e, rls_32(_SM3_TJ[j], j % 32)), 7)
            ss2 = ss1 ^ rls_32(a, 12)
            tt1 = mod_adds_32(_sm3_ff_j(a, b, c, j), d, ss2, self._w_[j])
            tt2 = mod_adds_32(_sm3_gg_j(e, f, g, j), h, ss1, self._w[j])
            d = c
            c = rls_32(b, 9)
            b = a
            a = tt1
            h = g
            g = rls_32(f, 19)
            f = e
            e = _sm3_p0(tt2)
        for i, v in enumerate((v ^ n for v, n in zip(self._v, (a, b, c, d, e, f, g, h)))):
            self._v[i] = v

    def _process_block(self):
        buffer_view = memoryview(self._buffer)
        while (next_cursor := self._cursor + 64) <= len(self._buffer):
            block_in = buffer_view[self._cursor:next_cursor]
            self._cf(block_in)
            self._cursor = next_cursor
        buffer_view.release()

        if self._cursor > self._buffer_limit:
            self._buffer = self._buffer[self._cursor:]
            self._offset += self._cursor
            self._cursor = 0

    def update(self, message: bytes):
        self._buffer.extend(message)
        while (next_cursor := self._cursor + 64) < len(self._buffer):
            self._process_block()
            self._cursor = next_cursor

    def digest(self) -> bytes:
        mbl = len(self._buffer) + self._offset  # 消息的最终长度（字节数）
        l = mbl * 8  # 消息的最终长度（比特数）
        k = (mbl + 9) % 64  # 消息加0x80填充+8字节长度结尾填充以后，还需要填充0x00的字节数
        self._buffer.append(0x80)  # 消息填充
        if k > 0:
            self._buffer.extend((0x00 for _ in range(64 - k)))
        self._buffer.extend(l.to_bytes(8, byteorder='big'))
        self._process_block()
        assert self._cursor == len(self._buffer)

        result = bytearray()
        for n in self._v:
            result.extend(n.to_bytes(4, byteorder='big', signed=False))
        return bytes(result)

