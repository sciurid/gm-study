
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


REMAINDER_P_BIG_ENDIAN = 0b10000111 # x^7 + x^2 + x + 1
REMAINDER_P_LITTLE_ENDIAN = p = 0b11100001 << 120  # x^7 + x^2 + x + 1

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


