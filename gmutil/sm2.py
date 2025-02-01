from typing import Optional, Tuple
import secrets
from .sm3 import sm3_hash, sm3_kdf
from .calculation import *
import logging

logger = logging.getLogger(__name__)

SM2_ECLIPSE_CURVE = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'x': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7',
    'y': 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'
}

SM2_P = int(SM2_ECLIPSE_CURVE['p'], base=16)
SM2_N = int(SM2_ECLIPSE_CURVE['n'], base=16)
SM2_A = int(SM2_ECLIPSE_CURVE['a'], base=16)
SM2_B = int(SM2_ECLIPSE_CURVE['b'], base=16)
SM2_X = int(SM2_ECLIPSE_CURVE['x'], base=16)
SM2_Y = int(SM2_ECLIPSE_CURVE['y'], base=16)
SM2_P_BYTE_LEN = SM2_P.bit_length() // 8


def p_add(a: int, b: int) -> int:
    return add_mod_prime(SM2_P, a, b)


def p_adds(*args):
    return adds_mod_prime(SM2_P, *args)


def p_minus(a: int, b: int) -> int:
    return minus_mod_prime(SM2_P, a, b)


def p_mul(a: int, b: int) -> int:
    return mul_mod_prime(SM2_P, a, b)


def p_muls(*args):
    return muls_mod_prime(SM2_P, *args)


def p_pow(n: int, k: int) -> int:
    return pow_mod_prime(SM2_P, n, k)


def p_div(a: int, b: int) -> int:
    return (a * inverse_mod_prime(SM2_P, b)) % SM2_P


def p_sqrt(n: int) -> Optional[int]:
    return square_root_mod_prime(SM2_P, n)


def on_curve(x: int, y: int) -> int:
    """检查点(x,y)是否在SM2椭圆曲线上"""
    left = (y ** 2) % SM2_P
    right = (x ** 3 + SM2_A * x + SM2_B) % SM2_P
    return left == right


def calculate_y(x: int) -> int:
    """根据SM2椭圆曲线上点的x计算对应的y"""
    return p_sqrt((x ** 3 + SM2_A * x + SM2_B) % SM2_P)


def _i2h(n: int) -> Optional[str]:
    """将整数值转化为长度为ECC的HEX字符串，用于点坐标的显示"""
    return _i2b(n).hex()


def _i2b(n: int):
    """将整数值转化为长度为ECC的字节串，用于点坐标的转换"""
    return int.to_bytes(n, length=SM2_P_BYTE_LEN, byteorder="big")


def jacobian_add(x1: Optional[int], y1: Optional[int], x2: Optional[int], y2: Optional[int])\
        -> Union[Tuple[None, None], Tuple[int, int]]:
    """GB/T 32918.1-2016 A.1.2.3.2 Jacobian加重射影坐标系上的点加法。

    比仿射坐标系下的计算量要小。
    """
    assert (x1 is None) == (y1 is None)
    assert (x2 is None) == (y2 is None)
    if x1 is None:
        if x2 is None:  # O + O = O
            return None, None
        else:
            return x2, y2  # O + P = P
    else:
        if x2 is None:
            return x1, y1  # P + O = P

    assert on_curve(x1, y1)
    assert on_curve(x2, y2)

    if x1 == x2:
        if y1 == y2:  # 倍点
            l1 = p_add(p_muls(x1, x1, 3), SM2_A)
            l2 = p_muls(x1, y1, y1, 4)
            l3 = p_mul(p_pow(y1, 4), 8)
            x3_ = p_mul(l1, l1) - p_mul(l2, 2)
            y3_ = p_minus(p_mul(l1, p_minus(l2, x3_)), l3)
            z3_ = p_mul(2, y1)

            d = p_mul(z3_, z3_)
            x3 = p_div(x3_, d)
            d = p_mul(d, z3_)
            y3 = p_div(y3_, d)
            return x3, y3

        else:  # 逆元素相加
            assert p_add(y1, y2) == 0
            return None, None
    else:
        l1 = x1
        l2 = x2
        l3 = p_minus(l1, l2)
        l4 = y1
        l5 = y2
        l6 = p_minus(l4, l5)
        l7 = p_add(l1, l2)
        l8 = p_add(l4, l5)

        l3_2 = p_mul(l3, l3)
        l3_3 = p_mul(l3_2, l3)
        x3_ = p_minus(p_mul(l6, l6), p_mul(l7, l3_2))
        y3_ = p_minus(p_mul(l6, p_minus(p_mul(l1, l3_2), x3_)), p_mul(l4, l3_3))
        z3_ = l3

        d = p_mul(z3_, z3_)
        x3 = p_div(x3_, d)
        d = p_mul(d, z3_)
        y3 = p_div(y3_, d)
        return x3, y3


class SM2Point:
    """SM2椭圆曲线上的整数点，简称SM2点"""

    def __init__(self, x: Optional[int], y: Optional[int]):
        """根据x坐标和y坐标构造SM2点

        如果x和y都是None，则表示无穷远点O
        """
        assert (x is None and y is None) or (0 <= x < SM2_P and 0 <= y < SM2_P)
        self._x = x
        self._y = y
        assert (self._x is None) == (self._y is None)
        if self._x is not None and not on_curve(x, y):  # 检验是否在椭圆曲线上
            raise ValueError(f"点{_i2h(x)} {_i2h(y)}不在SM2椭圆曲线上")

    @property
    def x(self) -> int:
        return self._x

    @property
    def x_octets(self) -> bytes:
        return _i2b(self._x)

    @property
    def y(self) -> int:
        return self._y

    @property
    def y_octets(self) -> bytes:
        return _i2b(self._y)

    def __add__(self, other: 'SM2Point'):
        """SM2点相加"""
        if self._x is None:  # 无穷远点
            # assert self._y is None
            return other

        if other._x is None:  # 无穷远点
            # assert other._y is None
            return self

        if self._x == other._x:
            if self._y == other._y:  # 倍点规则，GB/T 32918.1-2016 3.2.3.1 d) (P4)
                assert self._y != 0
                _lambda_numerator = p_add(p_mul(3, p_pow(self._x, 2)), SM2_A)  # x ** 2 * 3 + a
                _lambda_denominator = p_mul(2, self._y)  # 2 * y
                _lambda = p_div(_lambda_numerator, _lambda_denominator)

                x = p_minus(p_pow(_lambda, 2), p_mul(2, self._x))  # lambda ** 2 - 2 * x
                y = p_minus(p_mul(_lambda, p_minus(self._x, x)), self._y)

                return SM2Point(x, y)
            if p_add(self._y, other._y) == 0:  # 互逆点相加结果为无穷远点O
                return SM2Point(None, None)

            raise ValueError(f"Impossible condition: {self} + {other}")
        else:  # 非互逆不同点相加规则，GB/T 32918.1-2016 3.2.3.1 d) (P4)
            _lambda_numerator = p_minus(other._y, self._y)  # y2 - y1
            _lambda_denominator = p_minus(other._x, self._x)  # x2 - x1
            _lambda = p_div(_lambda_numerator, _lambda_denominator)
            x = p_minus(p_pow(_lambda, 2), p_add(self._x, other._x))  # lambda ** 2 - x1 - x2
            y = p_minus(p_mul(_lambda, p_minus(self._x, x)), self._y)  # lambda * (x1 - x3) - y1
            return SM2Point(x, y)

    def __mul__(self, k: int) -> 'SM2Point':
        """SM2点的整数倍"""
        res = SM2Point(None, None)
        next_pow = self

        mask = 1
        for r in range(SM2_P_BYTE_LEN * 8):
            if k & mask != 0:
                res += next_pow
            mask <<= 1
            next_pow += next_pow
        return res

    def __rmul__(self, k: int) -> 'SM2Point':
        """SM2点的整数倍"""
        return self * k

    def __eq__(self, other: 'SM2Point') -> bool:
        """判断两个SM2点相等"""
        return self._x == other._x and self._y == other._y

    def is_zero_point(self) -> bool:
        """判断是否为无穷远点O"""
        return self._x is None

    @staticmethod
    def repr_uncompressed(p: 'SM2Point') -> bytes:
        """SM2点的非压缩表示（04开头）
        GB/T 32918.1-2016 4.2.9 c)
        """
        buffer = bytearray()
        buffer.append(0x04)
        buffer.extend(_i2b(p.x))
        buffer.extend(_i2b(p.y))
        return bytes(buffer)

    @staticmethod
    def repr_compressed(p: 'SM2Point') -> bytes:
        """SM2点的压缩表示（02或03开头）
        GB/T 32918.1-2016 4.2.9 c)
        """
        buffer = bytearray()
        y_p = p.y & 0x01
        buffer.append(0x02 if y_p == 0 else 0x03)
        buffer.extend(_i2b(p.x))
        return bytes(buffer)

    @staticmethod
    def repr_hybrid(p: 'SM2Point') -> bytes:
        """SM2点的压缩表示（02或03开头）
        GB/T 32918.1-2016 4.2.9 d)
        """
        buffer = bytearray()
        y_p = p.y & 0x01
        buffer.append(0x06 if y_p == 0 else 0x07)
        buffer.extend(_i2b(p.x))
        buffer.extend(_i2b(p.y))
        return bytes(buffer)

    def to_bytes(self, fmt: str = 'uncompressed') -> bytes:
        """SM2点的字节串表示"""
        if fmt == 'uncompressed':
            return SM2Point.repr_uncompressed(self)
        elif fmt == 'compressed':
            return SM2Point.repr_compressed(self)
        elif fmt == 'hybrid':
            return SM2Point.repr_hybrid(self)
        else:
            raise ValueError('格式类型{}不支持，应当为：uncompressed/compressed/hybrid'.format(fmt))

    @staticmethod
    def from_bytes(octets: bytes) -> 'SM2Point':
        """从字节串表示中恢复SM2点
        GB/T 32918.1-2016 4.2.10
        """
        pc = octets[0]
        if pc == 0x04:
            if len(octets) != 2 * SM2_P_BYTE_LEN + 1:
                raise ValueError(f"SM2点未压缩格式长度{len(octets)}不符合标准，应当为{2 * SM2_P_BYTE_LEN + 1}")
            x = int.from_bytes(octets[1:SM2_P_BYTE_LEN + 1], byteorder='big')
            y = int.from_bytes(octets[SM2_P_BYTE_LEN + 1:], byteorder='big')
            return SM2Point(x, y)
        elif pc == 0x02 or pc == 0x03:
            y_p = 0x00 if pc == 0x02 else 0x01
            if len(octets) != SM2_P_BYTE_LEN + 1:
                raise ValueError(f"SM2点压缩格式长度{len(octets)}不符合标准，应当为{SM2_P_BYTE_LEN + 1}")
            x = int.from_bytes(octets[1:], byteorder='big')
            y_pow = p_adds(p_pow(x, 3), p_mul(SM2_A, x), SM2_B)  # GB/T 32918.1-2016 A.5.2
            y = p_sqrt(y_pow)

            if y & 0x01 == y_p:
                return SM2Point(x, y)
            else:
                return SM2Point(x, SM2_P - y)
        elif pc == 0x06 or pc == 0x07:
            y_p = 0x00 if pc == 0x06 else 0x01
            y = int.from_bytes(octets[SM2_P_BYTE_LEN + 1:], byteorder='big')
            if len(octets) != 2 * SM2_P_BYTE_LEN + 1:
                raise ValueError(f"SM2点混合格式长度{len(octets)}不符合标准，应当为{2 * SM2_P_BYTE_LEN + 1}")
            x = int.from_bytes(octets[1:], byteorder='big')
            ry_pow = p_adds(p_pow(x, 3), p_mul(SM2_A, x), SM2_B)
            ry = p_sqrt(ry_pow)

            if ry & 0x01 == y_p:
                ry = SM2_P - ry
            if ry != y:
                raise ValueError("SM2点混合格式中存储的y值与x值和pc值恢复出的不一致")

        else:
            raise ValueError(f"SM2点的字节串表示PC值错误（{pc:02x}）")

    def __repr__(self):
        """SM2点的显示表示"""
        if self.is_zero_point():
            return "Point: O"
        return f'Point(x={self.x_octets.hex()}, y={self.y_octets.hex()})'


POINT_G = SM2Point(SM2_X, SM2_Y)  # SM2曲线的基点G

_POINT_G_EXPONENT_2_VALUES = []  # 基点G的2的幂倍列表，用于快速计算公钥


def _init_quick_mul_g_point():
    """初始化基点G的2的幂倍列表，用于快速计算公钥"""
    global _POINT_G_EXPONENT_2_VALUES
    if len(_POINT_G_EXPONENT_2_VALUES) == 0:
        _gbv = POINT_G
        for i in range(SM2_P_BYTE_LEN * 8):
            _POINT_G_EXPONENT_2_VALUES.append(_gbv)
            _gbv += _gbv

    # for i in range(ECC_LEN * 8):
    #     assert G_POINT_BIT_VALUES[i]  == G_POINT * (1 << i)


def quick_mul_g_point(n: int) -> 'SM2Point':
    """快速计算倍乘基点G的方法"""
    _init_quick_mul_g_point()
    global _POINT_G_EXPONENT_2_VALUES
    p = SM2Point(None, None)
    mask = 1
    for i in range(SM2_P_BYTE_LEN * 8):
        if n & mask != 0:
            p += _POINT_G_EXPONENT_2_VALUES[i]
        mask <<= 1
    return p


DEFAULT_USER_ID = '1234567812345678'.encode()
"""用户身份ID的默认值为0x1234567812345678（GM/T 0009-2023 7 用户身份标识ID的默认值）"""


def generator_z(p: SM2Point, uid: bytes) -> bytes:
    """SM2预处理：根据用户身份ID和公钥计算出头部值

    GB/T 32918.2-2016 5.5
    :param p: SM2Point 公钥SM2点
    :param uid: 用户身份ID，长度不超过0xff
    :return: bytes 头部值
    """
    if len(uid) > 0xff:
        raise ValueError("用户ID长度超出两个字节限制")

    entl = (len(uid) * 8).to_bytes(2, byteorder='big')
    buffer = bytearray()
    buffer.extend(entl)
    buffer.extend(uid)
    buffer.extend(_i2b(SM2_A))
    buffer.extend(_i2b(SM2_B))
    buffer.extend(_i2b(SM2_X))
    buffer.extend(_i2b(SM2_Y))
    buffer.extend(_i2b(p.x))
    buffer.extend(_i2b(p.y))
    logger.debug('预处理输入: %s', buffer.hex())
    return sm3_hash(buffer)


class SM2PublicKey:
    def __init__(self, point: SM2Point):
        self._point = point

    @property
    def point(self):
        return self._point

    def __repr__(self):
        return '({},{})'.format(self._point.x_octets.hex().upper(), self._point.y_octets.hex().upper())

    @property
    def octets(self) -> bytes:
        return SM2Point.repr_uncompressed(self._point)

    def generate_z(self, uid: bytes = DEFAULT_USER_ID) -> bytes:
        """根据本公钥计算出头部值

        :param uid: 用户身份ID，长度不超过0xffff
        :return: 头部值
        """
        return generator_z(self._point, uid)

    def verify(self, message: bytes, signature: bytes, uid: bytes = DEFAULT_USER_ID) -> bool:
        """SM2公钥验签

        GB/T 32918.2-2016 7 (P4)
        :parm message: 待验签消息
        :parm signature: 签名数据，由r和s直接拼接成的数据，不包含任何数据头和格式
        :parm id_a: 用户ID，长度不超过0xffff
        :return: 验签结果
        """
        if len(signature) != 2 * SM2_P_BYTE_LEN:
            raise ValueError("签名数据长度错误（{}），请检查是否包含了额外的数据头或其他格式".format(len(signature)))
        r = int.from_bytes(signature[0:SM2_P_BYTE_LEN], byteorder='big')
        logger.debug("r=%s", signature[0:SM2_P_BYTE_LEN].hex())
        s = int.from_bytes(signature[SM2_P_BYTE_LEN:], byteorder='big')
        logger.debug("s=%s", signature[SM2_P_BYTE_LEN:].hex())
        buffer = bytearray(generator_z(self._point, uid))
        buffer.extend(message)
        e = int.from_bytes(sm3_hash(buffer), byteorder='big', signed=False)
        t = (r + s) % SM2_N  # Prove: t == (k + r) / (1 + d)
        if t == 0:
            return False

        pr = POINT_G * s + self._point * t  # Prove: pr == [k]G
        logger.debug("[k]G=%s", pr)
        vr = (e + pr.x) % SM2_N
        logger.debug("r=%064x", vr)
        return vr == r

    def encrypt(self, message: bytes, mode: str = 'C1C3C2') -> bytes:
        """SM2公钥加密

        GB/T 32918.4-2016 6 (P4)
        :param message: 待加密消息
        :param mode: GB/T 32918.2-2016规定的是C1C3C2格式，有些历史遗留的非标情况是C1C2C3格式
        :return: 密文
        """

        while True:
            k = secrets.randbelow(SM2_N - 1) + 1
            logger.debug("k=%s", _i2h(k))
            buffer = bytearray()

            p1 = POINT_G * k
            c1 = p1.to_bytes()
            logger.debug("[k]G=%s", p1)

            buffer.clear()
            p2 = self._point * k
            logger.debug("[k]P=%s", p2)
            buffer.extend(p2.x_octets)
            buffer.extend(p2.y_octets)
            m_len = len(message)
            t = sm3_kdf(bytes(buffer), m_len)
            logger.debug("   t=%s", t.hex())
            if t == 0:
                continue

            logger.debug("   m=%s", message.hex())
            buffer.clear()
            for i in range(m_len):
                buffer.append(t[i] ^ message[i])
            c2 = bytes(buffer)
            logger.debug("   c=%s", c2.hex())

            buffer.clear()
            buffer.extend(p2.x_octets)
            buffer.extend(message)
            buffer.extend(p2.y_octets)
            c3 = bytes(sm3_hash(buffer))
            logger.debug("   h=%s", c3.hex())

            buffer.clear()
            if mode == 'C1C3C2':
                buffer.extend(c1)
                buffer.extend(c3)
                buffer.extend(c2)
                return bytes(buffer)
            elif mode == 'C1C2C3':
                buffer.extend(c1)
                buffer.extend(c2)
                buffer.extend(c3)
                return bytes(buffer)
            else:
                raise ValueError('Mode must be C1C3C2 or C1C2C3C')


class SM2PrivateKey:
    def __init__(self, secret: Optional[int] = None):
        assert secret is None or 0 < secret < SM2_N - 1
        self._secret = secrets.randbelow(SM2_N - 2) + 1 if secret is None else secret
        self._pub_key = None

    @property
    def value(self):
        return self._secret

    def get_public_key(self) -> SM2PublicKey:
        if self._pub_key is None:
            self._pub_key = SM2PublicKey(quick_mul_g_point(self._secret))
        return self._pub_key

    @property
    def point(self):
        return self.get_public_key().point

    def to_bytes(self) -> bytes:
        return int.to_bytes(self._secret, length=SM2_P_BYTE_LEN, byteorder='big')

    @staticmethod
    def from_bytes(octets: bytes) -> 'SM2PrivateKey':
        return SM2PrivateKey(int.from_bytes(octets, byteorder='big', signed=False))

    def __repr__(self):
        return self.to_bytes().hex().upper()

    def sign(self, message: bytes, id_a: bytes = DEFAULT_USER_ID) -> bytes:
        """SM2私钥签名

        GB/T 32918.2-2016 6 (P3)
        签名使用的哈希算法为SM3
        :param message: 待签名数据
        :param id_a:  用户ID，长度不超过0xffff，默认值为0x1234567812345678（GM/T 0009-2023 7 用户身份标识ID的默认值）
        :return: 签名数据
        """
        buffer = bytearray(generator_z(self.point, id_a))
        buffer.extend(message)
        e = int.from_bytes(sm3_hash(buffer), byteorder='big', signed=False)

        while True:
            k = secrets.randbelow(SM2_N - 1) + 1
            p = POINT_G * k
            logger.debug('[k]G=%s', p)
            r = (e + p.x) % SM2_N
            if r == 0 or r + k == SM2_N:
                continue
            logger.debug("r=%s", _i2h(r))
            s = (inverse_mod_prime(SM2_N, 1 + self._secret) * (k - r * self._secret) % SM2_N) % SM2_N
            if s == 0:
                continue
            logger.debug("s=%s", _i2h(s))
            buffer.clear()
            buffer.extend(_i2b(r))
            buffer.extend(_i2b(s))
            return bytes(buffer)

    def decrypt(self, cipher_text: bytes, mode: str = 'C1C3C2') -> bytes:
        """SM2私钥解密

        GB/T 32918.4-2016 7 (P4)
        :param cipher_text: 密文
        :param mode: GB/T 32918.2-2016规定的是C1C3C2格式，有些历史遗留的非标情况是C1C2C3格式
        :return: 明文
        """

        if mode == 'C1C3C2':
            pivot_1 = 2 * SM2_P_BYTE_LEN + 1
            pivot_2 = pivot_1 + 32
            c1 = cipher_text[0:pivot_1]
            c3 = cipher_text[pivot_1:pivot_2]
            c2 = cipher_text[pivot_2:]
        elif mode == 'C1C2C3':
            pivot_1 = 2 * SM2_P_BYTE_LEN + 1
            pivot_2 = len(cipher_text) - 32
            c1 = cipher_text[0:pivot_1]
            c2 = cipher_text[pivot_1:pivot_2]
            c3 = cipher_text[pivot_2:]
        else:
            raise ValueError('Mode must be C1C3C2 or C1C2C3C')

        p1 = SM2Point.from_bytes(c1)
        logger.debug("[k]G=%s", p1)
        p2 = p1 * self.value

        logger.debug("[k]P=%s", p2)
        m_len = len(cipher_text) - pivot_2

        buffer = bytearray()
        buffer.extend(p2.x_octets)
        buffer.extend(p2.y_octets)
        t = sm3_kdf(buffer, m_len)
        logger.debug("   t=%s", t.hex())
        logger.debug("   c=%s", c2.hex())
        buffer.clear()
        for i in range(m_len):
            buffer.append(c2[i] ^ t[i])
        message = bytes(buffer)
        logger.debug("   m=%s", message.hex())

        buffer.clear()
        buffer.extend(p2.x_octets)
        buffer.extend(message)
        buffer.extend(p2.y_octets)
        c3r = sm3_hash(buffer)

        logger.debug("h[o]=%s", c3.hex())
        logger.debug("h[r]=%s", c3r.hex())

        if c3 != c3r:
            raise ValueError("解密错误")
        else:
            return message


class SM2KeyExchange:
    """
    GB/T 32918.3-2016 规定的密钥交换协议
    """

    def __init__(self, private_key: Optional[SM2PrivateKey] = None, uid: bytes = DEFAULT_USER_ID, k_byte_len: int = 16):
        """密钥交换协议的用户公共类

        GB/T 32918.3-2016 6.1 密钥交换协议
        如果不采用B8、A9、A10、B10规定的选项步骤，则可以直接使用本类进行密钥交换。示例见单元测试。

        :param private_key 用户密钥
        :param uid 用户身份ID
        """
        self._private_key = SM2PrivateKey() if private_key is None else private_key
        self._public_key = self._private_key.get_public_key()
        self._uid = uid
        self._k_byte_len = k_byte_len
        # GB/T 32918.3-2016 6.1 A1-A2/B1-B2
        r = secrets.randbelow(SM2_N - 1) + 1
        self._point_r = POINT_G * r

        # GB/T 32918.3-2016 6.1 A1-A2/B1-B2
        x_bar = SM2KeyExchange._x_bar(self._point_r.x)
        self._t = (self._private_key.value + x_bar * r) % SM2_N

        # 在密钥计算阶段保存用于B8、A9、A10、B10步骤的数据
        self._exchanged_key = None
        self._other_z = None
        self._own_z = None
        self._point_uv = None
        self._other_point_r = None

    W = ((SM2_N - 1).bit_length() + 1) // 2 - 1

    @staticmethod
    def _x_bar(x: int) -> int:
        return (1 << SM2KeyExchange.W) + x & ((1 << SM2KeyExchange.W) - 1)

    @property
    def public_key(self) -> SM2PublicKey:
        return self._public_key

    @property
    def uid(self):
        return self._uid

    @property
    def point_r(self) -> SM2Point:
        """GB/T 32918.3-2016 6.1 A3/B3
        用于发给对方的R_A/R_B点
        """
        return self._point_r

    @property
    def exchanged_key(self) -> bytes:
        return self._exchanged_key

    def send(self) -> Tuple[SM2PublicKey, SM2Point, bytes]:
        return self._public_key, self._point_r, self._uid

    def calculate_key(self, party_a: bool, public_key_other: SM2PublicKey, point_r_other: SM2Point,
                      uid_other: bytes) -> bytes:
        """根据对方发来的R_A/R_B点协商形成密钥

        :param party_a 是否为用户A（先发送点R的一方）
        :param public_key_other: 对方的公钥
        :param point_r_other SM2Point 对方发来的点
        :param uid_other SM2Point 对方的用户身份ID
        :return: bytes 协商形成的密钥
        """

        self._other_point_r = point_r_other
        x_bar_other = SM2KeyExchange._x_bar(point_r_other.x)
        self._point_uv = (public_key_other.point + point_r_other * x_bar_other) * self._t
        if self._point_uv.is_zero_point():
            raise ValueError("密钥协商协商失败：计算出点V为无穷远点")

        buffer = bytearray()
        buffer.extend(self._point_uv.x_octets)
        buffer.extend(self._point_uv.y_octets)

        self._own_z = self.public_key.generate_z(self.uid)
        self._other_z = public_key_other.generate_z(uid_other)
        if party_a:
            buffer.extend(self._own_z)
            buffer.extend(self._other_z)
        else:
            buffer.extend(self._other_z)
            buffer.extend(self._own_z)

        self._exchanged_key = sm3_kdf(buffer, self._k_byte_len)
        return self._exchanged_key


class SM2KeyExchangePartyA(SM2KeyExchange):
    def __init__(self, private_key: Optional[SM2PrivateKey] = None, uid: bytes = DEFAULT_USER_ID, k_byte_len: int = 16):
        """密钥交换协议的用户B类

        GB/T 32918.3-2016 6.1 密钥交换协议
        采用B8、A9、A10、B10规定的选项步骤。

        :param private_key 用户密钥
        :param uid 用户身份ID
        """
        super().__init__(private_key, uid, k_byte_len)

    def send_1(self) -> Tuple[int, SM2PublicKey, SM2Point, bytes]:
        return self._k_byte_len, self._public_key, self._point_r, self._uid

    def receive_2(self, public_key_b: SM2PublicKey, point_r_b: SM2Point, uid_b: bytes, s_b: bytes):
        self.calculate_key(True, public_key_b, point_r_b, uid_b)
        # 步骤B8，计算S_1
        s_1 = calculate_sab(False, self._point_uv, self._own_z, self._other_z,
                            self.point_r, self._other_point_r)
        if s_1 != s_b:
            raise ValueError("密钥确认步骤（A9）失败：S_B={}, S_1={}".format(s_b.hex(), s_1.hex()))

    def send_3(self) -> Tuple[bytes]:
        s_a = calculate_sab(True, self._point_uv, self._own_z, self._other_z,
                            self.point_r, self._other_point_r)
        return (s_a,)


class SM2KeyExchangePartyB(SM2KeyExchange):
    def __init__(self, private_key: Optional[SM2PrivateKey] = None, uid: bytes = DEFAULT_USER_ID, k_byte_len: int = 16):
        """密钥交换协议的用户B类

        GB/T 32918.3-2016 6.1 密钥交换协议
        采用B8、A9、A10、B10规定的选项步骤。

        :param private_key 用户密钥
        :param uid 用户身份ID
        """
        super().__init__(private_key, uid, k_byte_len)
        self._s_b = None

    def receive_1(self, k_byte_len: int, public_key_a: SM2PublicKey, point_r_a: SM2Point, uid_a: bytes):
        self._k_byte_len = k_byte_len
        self.calculate_key(False, public_key_a, point_r_a, uid_a)

        # 步骤B8，计算S_B
        self._s_b = calculate_sab(False, self._point_uv, self._other_z, self._own_z,
                                  self._other_point_r, self.point_r)

    def send_2(self):
        return self._public_key, self._point_r, self._uid, self._s_b

    def receive_3(self, s_a: bytes):
        s_2 = calculate_sab(True, self._point_uv, self._other_z, self._own_z,
                            self._other_point_r, self.point_r)
        if s_2 != s_a:
            raise ValueError("密钥确认步骤（A9）失败：S_B={}, S_1={}".format(s_a.hex(), s_2.hex()))


def calculate_sab(is_a: bool, point_uv, za, zb, point_ra, point_rb):
    # 步骤B8、A9，计算S_B/S_1
    buffer = bytearray()
    buffer.extend(point_uv.x_octets)
    buffer.extend(za)  # Z_A
    buffer.extend(zb)  # Z_B
    buffer.extend(point_ra.x_octets)  # x_1
    buffer.extend(point_ra.y_octets)  # y_1
    buffer.extend(point_rb.x_octets)  # x_2
    buffer.extend(point_rb.y_octets)  # y_2
    mid = sm3_hash(buffer)
    buffer.clear()
    buffer.append(0x03 if is_a else 0x02)
    buffer.extend(point_uv.y_octets)
    buffer.extend(mid)
    return sm3_hash(buffer)
