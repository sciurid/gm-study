from typing import Tuple, Optional
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


def minus_mod_prime(p: int, a: int, b: int ) -> int:
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

