from typing import Tuple, Optional, Union, Literal
import secrets


def add_mod_prime(p: int, a: int, b: int) -> int:
    """模素数加法"""
    return (a + b) % p


def adds_mod_prime(p: int, *args):
    """模素数连加"""
    res = 0
    for arg in args:
        res = add_mod_prime(p, res, arg)
    return res


def minus_mod_prime(p: int, a: int, b: int) -> int:
    """模素数减法"""
    return (a - b) % p


def mul_mod_prime(p: int, a: int, b: int) -> int:
    """模素数乘法"""
    return (a * b) % p


def pow_mod_prime(p: int, n: int, k: int):
    """快速计算n ** k % p的方法"""
    if k == 0:
        return 1

    res = 1
    mask = 1
    next_pow = n
    for _ in range(k.bit_length()):
        if k & mask != 0:
            res = res * next_pow % p
        next_pow = next_pow ** 2 % p
        mask = mask << 1

    # assert (n ** k) % p == res
    return res


def ex_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展的欧几里得算法
    通常用于求最大公约数和模素数求逆
    r = gcd(a, b)
    r = a * x + b * y
    """
    if a < b:
        a, b = b, a

    if b == 0:
        return a, 1, 0

    r, x, y = ex_gcd(b, a % b)
    x, y = y, x - (a // b) * y

    # assert r == a * x + b * y
    return r, x, y


def inverse_mod_prime(p: int, n: int) -> Optional[int]:
    """求p素域中的乘法逆元"""
    assert 0 < n < p
    r, x, y = ex_gcd(p, n)
    assert r == 1
    return y % p


def _lucas_quick(p, x, y, k):
    """生成Lucas序列的U mod p和V mod p

    GB/T 32918.1-2016 B.1.3 (P29)
    """
    delta = x ** 2 - 4 * y
    r = k.bit_length() - 1
    u = 1
    v = x

    for i in range(r - 1, -1, -1):
        u, v = (u * v), ((v ** 2 + u ** 2 * delta) // 2)
        if k & (0x01 << i) != 0:
            u, v = (x * u + v) // 2, (x * v + delta * u) // 2
    return u % p, v % p


def _lucas_sequence(p, x, y, k):
    """生成Lucas序列的U mod p和V mod p

    GB/T 32918.1-2016 B.1.3 (P29)
    """
    u_0, u_1 = 0, 1
    v_0, v_1 = 2, x
    for n in range(2, k + 1):
        u_n, v_n = x * u_1 - y * u_0, x * v_1 - y * v_0
        u_0, v_0 = u_1, v_1
        u_1, v_1 = u_n, v_n
    return u_1 % p, v_1 % p


def square_root_mod_prime(p: int, g: int) -> Optional[int]:
    """求解模素数平方根

    GB/T 32918.1-2016 B.1.3 (P29)
    """
    if g == 0:
        return 0

    if p % 4 == 3:
        u = (p - 3) // 4
        y = pow_mod_prime(p, g, u + 1)
        z = (y ** 2) % p
        if z == g:
            return y
        else:
            return None

    if p % 8 == 5:
        u = (p - 5) // 8
        z = pow_mod_prime(p, g, 2 * u + 1)
        if (z - 1) % p == 0:
            y = pow_mod_prime(p, g, u + 1)
            return y
        elif (z + 1) % p == 0:
            y = (pow_mod_prime(p, (4 * g), u) * 2 * g) % p
            return y
        else:
            return None

    if p % 8 == 1:
        while True:
            y = g
            x = secrets.randbelow(p)
            u, v = _lucas_quick(p, x, g, ((p - 1) // 8) * 4 + 1)
            if (v ** 2 - 4 * y) % p == 0:
                return (v // 2) % p if v % 2 == 0 else ((v + p) // 2) % p
            if (u - 1) % p != 0 and (u + 1) % p != 0:
                return None

    raise ValueError(f"Number {p} is not a prime.")


def xor_on_bytes(x: Union[bytes, bytearray, memoryview], y: Union[bytes, bytearray, memoryview],
                 byteorder: Literal['big', 'little'] = 'big', signed=False,
                 bytes_or_int: Literal['bytes', 'int'] = 'bytes') -> Union[bytes, int]:
    x_int = int.from_bytes(x, byteorder=byteorder, signed=signed)
    y_int = int.from_bytes(y, byteorder=byteorder, signed=signed)

    res = x_int ^ y_int
    if bytes_or_int == 'bytes':
        return res.to_bytes(max(len(x), len(y)), byteorder=byteorder, signed=signed)
    if bytes_or_int == 'int':
        return res

    raise ValueError('结果类型必须是"bytes"或"int"')


MASK_128_ONES = (0x01 << 128) - 1
MASK_128_BIT = 0x01 << 128
MASK_127_BIT = 0x01 << 127
REMAINDER = 0b11100001 << 120  # 多项式模的剩余项，即 1 + x + x^2 + x^7


def mul_gf_2_128(u: int, v: int, big_endian=False) -> int:
    """伽罗华域GF(2^128)上的多项式乘法。

    GB/T 15852.3-2019规定的模多项式为 m(x) = 1 + x + x^2 + x^7 + x^128。
    :param big_endian: True表示big-endian，即从高位到低位比特分别表示从x^0到x^127；False则表示为little-endian，反之。
    例如128位二进制数1001....1101，big-endian表示 x^127 + x^124 + ... + x^3 + x^2 + 1，
    little-endian表示 1 + x^3 + ... + x^124 + x^125 + x^127。
    注意：GB/T 15852.3-2019规定实现中的多项式二进制系数是little-endian。

    :param u: 多项式的二进制表示
    :param v: 多项式的二进制表示
    :return: u和v在GF(2^128)上的多项式乘法结果
    """
    assert u.bit_length() <= 128
    assert v.bit_length() <= 128

    w = 0  # 乘法结果
    z = u  # 在迭代中对应每个比特位的乘法结果，初始值为u，即表示u_0 + u_1 * x + u_2 * x^2 + ... + u_127 * x^127，其中x为不定元。

    # 从v的表示的多项式的0次项开始依次向右（即从多项式的0次项开始到127次项）
    # 如果v的某位为1，则结果加上对应位的z，即u * x^i
    # 如果对应某个比特位i上的z表示多项式z[i] = z_0 + z_1 * x + z_2 * x^2 + ... + z_127 * x^127 = u * x^i
    # 那么下个比特位上的多项式z[i+1] = u * x^{i+1} =  0 + z_0 * x + z_1 * x^2 + z_2 * x^3 + ... + z_127 * x^128
    # 如果z_127 = 0，那么模m(x)结果不变；如果z_127 = 1，则模m(x)的结果为z + m(x) - x^128
    # 见《密码编码学与网络安全：原理与实践（第八版）》第94页“5.6.4计算上的考虑”

    if big_endian:
        for _ in range(128):
            # 通过对v不断右移实现从右向左逐位检查
            if v & 0x01 != 0:
                w ^= z  # 如果该位为1，则将对应的 z= u * x^i 加上。
            v >>= 1

            # z_127 = 1时，则下一个z应当为z + m(x) - x^128
            if z & MASK_127_BIT == 0:
                z = (z << 1)
            else:
                z = ((z << 1) ^ 0b10000111) & MASK_128_ONES
        return w
    else:
        v_mask = MASK_127_BIT
        for i in range(0, 128):
            if v & v_mask != 0:  # 通过对v_mask的右移实现对v的从左向右逐位检查
                w = w ^ z  # 如果该位为1，则将对应的 z= u * x^i 加上。
            v_mask >>= 1

            # z_127 = 1时，则下一个z应当为z * x + m(x) - x^128，其中x^128项随右移自然减掉
            if z & 0x01 == 0:
                z = z >> 1  # 下一个z的
            else:
                z = (z >> 1) ^ REMAINDER

    return w


REMAINDER_P_BIG_ENDIAN = 0b10000111  # x^7 + x^2 + x + 1
REMAINDER_P_LITTLE_ENDIAN = 0b11100001 << 120  # x^7 + x^2 + x + 1


def mul_gf_2_128_alt(u: int, v: int, big_endian: bool = False):
    """伽罗华域GF(2^128)上的多项式乘法（另一实现）。

    GB/T 15852.3-2019规定的模多项式为 m(x) = 1 + x + x^2 + x^7 + x^128。
    :param big_endian: True表示big-endian，即从高位到低位比特分别表示从x^0到x^127；False则表示为little-endian，反之。
    例如128位二进制数1001....1101，big-endian表示 x^127 + x^124 + ... + x^3 + x^2 + 1，
    little-endian表示 1 + x^3 + ... + x^124 + x^125 + x^127。
    注意：GB/T 15852.3-2019规定实现中的多项式二进制系数是little-endian。

    :param u: 多项式的二进制表示
    :param v: 多项式的二进制表示
    :return: u和v在GF(2^128)上的多项式乘法结果
    """

    # 采取逐位迭代计算的方式，对于v表示的多项式v_127 * x^127 + v_126 * x^126 + ... + v_2 * x^2 + v_1 * x + 1，其中x为不定元。
    # [0] m = 0
    # [1] m = m * x + u * v_127
    # [2] m = m * x + u * v_126 = u * (v_127 * x + v_126)
    # [3] m = m * x + u * v_125 = u * (v_127 * x^2 + v_126 + x + v_125)
    # ...
    # [128] m = m * x + u * v_0 = u * (v_127 * x^127 + v_126 * x^126 + v_125 * x^125 + ... + v_0) = u * v
    # 如果中间过程中m的x^128项为1，则m = m mod m(x) = m + x^7 + x^2 + x + 1 - x^128
    if big_endian:
        p = REMAINDER_P_BIG_ENDIAN
        m = 0
        v_bit = MASK_127_BIT
        for _ in range(128):  # 从v的最高次项到最低次项
            m = m << 1  # m * x
            if m & MASK_128_BIT:
                m = m ^ p  # x^128项为1，则mod m(x)
            if v & v_bit:  # v_i = 1时， m * x + u
                m = m ^ u
            v_bit >>= 1
        return m
    else:
        p = REMAINDER_P_LITTLE_ENDIAN
        m = 0
        for _ in range(128):  # 从v的最高次项到最低次项
            if m & 0x01:  # little-endian时x^128项在右移中自动消除
                m = (m >> 1) ^ p  # x^128项为1，则mod m(x)
            else:
                m = m >> 1
            if v & 0x01:  # v_i = 1时， m * x + u
                m = m ^ u
            v >>= 1
        return m
