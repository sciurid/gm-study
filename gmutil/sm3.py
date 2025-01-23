from typing import Union, Tuple, Sequence

# GB/T 32905-2016 4.1 初始值
_SM3_IV = (0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e)


# GB/T 32905-2016 4.2 常量
_SM3_TJ = tuple(0x79cc4519 if 0 <= j < 16 else 0x7a879d8a for j in range (0, 64))


def rls_32(x: int, n: int):
    """32位循环左移函数（Rotate Left Shift）：x <<< n
    """
    assert x.bit_length() <= 32
    if n >= 32:
        n = n % 32
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)


def mod_add_32(a: int, b: int):
    """模 2 ** 32 加法"""
    return (a + b) & 0xffffffff


def mod_adds_32(*args):
    """模 2 ** 32 连续加法"""
    s = 0
    for n in args:
        assert isinstance(n, int)
        s += n
    return s & 0xffffffff


def sm3_ff_j(x: int, y: int, z: int, j: int):
    """GB/T 32905-2016 4.3 布尔函数FF_j"""
    assert x.bit_length() <= 32
    assert y.bit_length() <= 32
    assert z.bit_length() <= 32
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        ret = (x & y) | (x & z) | (y & z)
    else:
        raise ValueError(f"j = {j}")
    return ret


def sm3_gg_j(x: int, y: int, z: int, j):
    """GB/T 32905-2016 4.3 布尔函数GG_j"""
    assert x.bit_length() <= 32
    assert y.bit_length() <= 32
    assert z.bit_length() <= 32
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (x & y) | ((~ x) & z)
    else:
        raise ValueError(f"j = {j}")
    return ret


def sm3_p0(x: int):
    """GB/T 32905-2016 4.4 置换函数P0"""
    assert x.bit_length() <= 32
    return x ^ rls_32(x, 9) ^ rls_32(x, 17)


def sm3_p1(x: int):
    """GB/T 32905-2016 4.4 置换函数P1"""
    assert x.bit_length() <= 32
    return x ^ rls_32(x, 15) ^ rls_32(x, 23)


def pad(m: Union[bytes, bytearray]) -> bytes:
    """GB/T 32905-2016 5.2 填充"""
    if isinstance(m, bytes):
        buffer = bytearray(m)
    elif isinstance(m, bytearray):
        buffer = m
    else:
        raise ValueError(f"Message type {type(m)} of {m} is not supported.")

    l = len(m) * 8
    k = (len(m) + 9) % 64
    buffer.append(0x80)
    if k > 0:
        buffer.extend((0x00 for _ in range(64 - k)))
    buffer.extend(l.to_bytes(8, byteorder='big'))

    return bytes(buffer)


def expand(b: bytes) -> Tuple[Sequence[int], Sequence[int]]:
    """GB/T 32905-2016 5.3.2 消息扩展"""
    assert len(b) == 64
    w = [int.from_bytes(b[i:i+4], byteorder='big', signed=False) for i in range(0, len(b), 4)]
    for j in range(16, 68):
        w.append(sm3_p1(w[j - 16] ^ w[j - 9] ^ rls_32(w[j - 3], 15))
                 ^ rls_32(w[j - 13], 7) ^ w[j - 6])

    w_ = []
    for j in range(0, 64):
        w_.append(w[j] ^ w[j + 4])

    return w, w_


def cf(v_i: tuple, b_i: bytes) -> tuple:
    """CF压缩函数：GB/T 32905-2016 5.3.3

    v_i: 迭代压缩输入32 bytes（256 bits）
    b_i: 消息分组输入32 bytes（256 bits）
    """
    assert len(v_i) == 8
    assert len(b_i) == 64

    w, w_ = expand(b_i)

    a, b, c, d, e, f, g, h = v_i
    for j in range(0, 64):
        ss1 = rls_32(
            mod_adds_32(rls_32(a, 12), e, rls_32(_SM3_TJ[j], j % 32)), 7)
        ss2 = ss1 ^ rls_32(a, 12)
        tt1 = mod_adds_32(sm3_ff_j(a, b, c, j), d, ss2, w_[j])
        tt2 = mod_adds_32(sm3_gg_j(e, f, g, j), h, ss1, w[j])
        d = c
        c = rls_32(b, 9)
        b = a
        a = tt1
        h = g
        g = rls_32(f, 19)
        f = e
        e = sm3_p0(tt2)
        # print(f'{j:02d}', [int.to_bytes(v, length=4, byteorder='big', signed=False).hex()
        #                    for v in (a, b, c, d, e, f, g, h)])
    return tuple(v ^ n for v, n in zip(v_i, (a, b, c, d, e, f, g, h)))


def sm3_hash(message: Union[bytes, bytearray]) -> bytes:
    padded = pad(message)
    v_0 = _SM3_IV
    for i in range(0, len(padded), 64):
        v_n = cf(v_0, padded[i:i + 64])
        v_0 = v_n

    buffer = bytearray()
    for n in v_n:
        buffer.extend(n.to_bytes(4, byteorder='big', signed=False))
    return bytes(buffer)


def sm3_kdf(data: Union[bytes, bytearray], m_len: int):
    """SM3密钥派生函数
    GB/T 32918.4-2016 6.4.3 (P3)
    data: 比特串
    m_len: 要派生出的密钥字节数
    """
    res = bytearray()
    buffer = bytearray()

    for i in range((m_len - 1) // 32 + 1):  # 以SM3的输出长度（256 bits=32 bytes）分块
        buffer.clear()
        buffer.extend(data)
        buffer.extend(int.to_bytes(i + 1, length=4, byteorder='big'))
        res.extend(sm3_hash(buffer))

    return bytes(res[0:m_len])






