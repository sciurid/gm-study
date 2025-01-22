import secrets

MASK_8 = ((0x01 << 8) - 1)

def mul_8_1(u: int, v: int):
    assert u.bit_length() <= 8
    assert v.bit_length() <= 8

    # {m(x) = x^8 + x^4 + x^3 + x + 1}
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
            z = ((z << 1) ^ 0b00011011) & MASK_8
        # print('Z:{:08b}'.format(z))
    return w


def mul_8_2(u: int, v: int):
    p = 0b100011011  # mpy modulo x^8+x^4+x^3+x+1
    m = 0  # m will be product
    for i in range(8):
        m = m << 1
        if m & 0b100000000:
            m = m ^ p
        if v & 0b010000000:
            m = m ^ u
        v = v << 1
    return m
    # {m(x) = x^8 + x^4 + x^3 + x + 1}



MASK_128_ONES = (0x01 << 128) - 1
MASK_128_BIT = 0x01 << 128
MASK_127_BIT = 0x01 << 127
REMAINDER = 0b11100001 << 120  # 多项式模的剩余项，即 1 + x + x^2 + x^7

def mul_gf_2_128_gbt(u: int, v: int) -> int:
    """GB/T 15852.3-2019规定的域GF(2^128)上的多项式乘法，模多项式为 m(x) = 1 + x + x^2 + x^7 + x^128。

    注意：标准实现中的多项式二进制系数是little-endian的，即从高位到低位比特分别表示从x^0到x^127。
    例如128位二进制数1001....1101表示 1 + x^3 + ... + x^124 + x^125 + x^127。
    与通常中的整数高位表示更高幂的习惯相反，需要注意移位顺序。
    """
    assert u.bit_length() <= 128
    assert v.bit_length() <= 128

    w = 0  # 乘法结果
    z = u  # 在迭代中对应每个比特位的乘法结果，初始值为u，即表示u_0 + u_1 * x + u_2 * x^2 + ... + u_127 * x^127
    v_mask = MASK_127_BIT
    for i in range(0, 128):  # 从v的最高位开始依次向右（即从多项式的0次项开始到127次项）
        if v & v_mask != 0:  # 如果v的某位为1，则结果加上对应位的z，即u * x^i
            w = w ^ z
        v_mask >>= 1

        # 迭代中，如果在某个比特位i上的z表示多项式z[i] = z_0 + z_1 * x + z_2 * x^2 + ... + z_127 * x^127 = u * x^i
        # 那么下个比特位上的多项式z[i+1] = u * x^{i+1} =  0 + z_0 * x + z_1 * x^2 + z_2 * x^3 + ... + z_127 * x^128
        # 如果z_127 = 0，那么模m(x)结果不变；如果z_127 = 1，则模m(x)的结果为z + m(x) - x^128
        # 见《密码编码学与网络安全：原理与实践（第八版）》第94页“5.6.4计算上的考虑”
        if z & 0x01 == 0:
            z = z >> 1
        else:
            z = (z >> 1) ^ REMAINDER

    return w



def mul_128_2(u: int, v: int, big_endian: bool = False):
    """域GF(2^128)上的多项式乘法，模多项式为 m(x) = 1 + x + x^2 + x^7 + x^128。

    :param u: 128-bit乘数
    :param v: 128-bit乘数
    :param big_endian: True表示big-endian，即从高位到低位比特分别表示从x^0到x^127；False则表示为little-endian，反之。
    例如128位二进制数1001....1101，big-endian表示 x^127 + x^124 + ... + x^3 + x^2 + 1，
    little-endian表示 1 + x^3 + ... + x^124 + x^125 + x^127。
    """
    if big_endian:
        p = (1 << 128) | 0b10000111
        m = 0
        for i in range(128):
            m = m << 1
            if m & MASK_128_BIT:
                m = m ^ p
            if v & MASK_127_BIT:
                m = m ^ u
            v <<= 1
        return m
    else:
        p = 0b11100001 << 120
        m = 0
        for i in range(128):
            if m & 0x01:
                m = (m >> 1) ^ p
            else:
                m = m >> 1
            if v & 0x01:
                m = m ^ u
            v >>= 1
        return m




def mul_128_3(x: int, y: int, big_endian: bool = False):
    """在GF(2^128)上的多项式乘法

    《密码编码学与网络安全：原理与实践（第八版）》第94页“5.6.4计算上的考虑”中的算法。
    :param x: 多项式的二进制表示
    :param y: 多项式的二进制表示
    :return: u和v在GF(2^128)上的多项式乘法结果
    """

    assert x.bit_length() <= 128
    assert y.bit_length() <= 128

    if big_endian:

        w = 0  # sum
        z = x  # {u \mul 2^i}
        for _ in range(128):
            if y & 0x01 != 0:
                w ^= z
            y >>= 1

            if z >> 127 == 0:  # b128 !=0 时，需要模{m(x)}
                z = (z << 1)
            else:
                z = ((z << 1) ^ 0b10000111) & MASK_128_ONES
        return w
    else:
        w = 0
        z = x
        y_bit = 0x01 << 127
        for _ in range(128):
            if y & y_bit != 0:
                w ^= z
            y_bit >>=1

            if z & 0x01 == 0:
                z >>= 1
            else:
                z = (z >> 1) ^ (0b11100001 << 120)
        return w




for i in range(128):
    u = secrets.randbits(8)
    v = secrets.randbits(8)

    # assert mul_8_2(u, v) == mul_8_1(u, v)


    r1 = int.to_bytes(mul_gf_2_128_gbt(u, v), length=16, byteorder='big', signed=False)
    print(r1.hex(' '))
    print('{:08b}'.format(r1[0]))
    r2 = int.to_bytes(mul_128_2(u, v, False), length=16, byteorder='big', signed=False)
    # r2 = int.to_bytes(mul_128_2(u, v, True), length=16, byteorder='big', signed=False)
    print(r2.hex(' '))
    print('{:08b}'.format(r2[0]))
    r3 = int.to_bytes(mul_128_3(u, v, False), length=16, byteorder='big', signed=False)
    # r3 = int.to_bytes(mul_128_3(u, v, True), length=16, byteorder='big', signed=False)
    print(r3.hex(' '))
    print('{:08b}'.format(r3[0]))
    assert r1 == r2 == r3


