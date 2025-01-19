from typing import Optional, Tuple
import secrets
from .sm3 import sm3_hash, sm3_kdf
from .calc import *
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

ECC_P = int(SM2_ECLIPSE_CURVE['p'], base=16)
ECC_N = int(SM2_ECLIPSE_CURVE['n'], base=16)
ECC_A = int(SM2_ECLIPSE_CURVE['a'], base=16)
ECC_B = int(SM2_ECLIPSE_CURVE['b'], base=16)
ECC_X = int(SM2_ECLIPSE_CURVE['x'], base=16)
ECC_Y = int(SM2_ECLIPSE_CURVE['y'], base=16)
ECC_LEN = ECC_P.bit_length() // 8


def p_add(a: int, b: int) -> int:
    return add_mod_prime(ECC_P, a, b)


def p_adds(*args):
    return add_mod_prime(ECC_P, *args)


def p_minus(a: int, b: int) -> int:
    return minus_mod_prime(ECC_P, a, b)


def p_mul(a: int, b: int) -> int:
    return mul_mod_prime(ECC_P, a, b)


def p_pow(n: int, k: int) -> int:
    return pow_mod_prime(ECC_P, n, k)


def p_div(a: int, b: int) -> int:
    return (a * inverse_mod_prime(ECC_P, b)) % ECC_P


def p_sqrt(n: int) -> Optional[int]:
    return square_root_mod_prime(ECC_P, n)


def on_curve(x: int, y: int) -> int:
    """检查点(x,y)是否在SM2椭圆曲线上"""
    left = (y ** 2) % ECC_P
    right = (x ** 3 + ECC_A * x + ECC_B) % ECC_P
    return left == right


def calculate_y(x: int) -> int:
    """根据SM2椭圆曲线上点的x计算对应的y"""
    return p_sqrt((x ** 3 + ECC_A * x + ECC_B) % ECC_P)


def _i2h(n: int) -> Optional[str]:
    """将整数值转化为长度为ECC的HEX字符串，用于点坐标的显示"""
    return _i2b(n).hex()


def _i2b(n: int):
    """将整数值转化为长度为ECC的字节串，用于点坐标的转换"""
    return int.to_bytes(n, length=ECC_LEN, byteorder="big")


class SM2Point:
    """SM2椭圆曲线上的整数点，简称SM2点"""
    def __init__(self, x: Optional[int], y: Optional[int]):
        """根据x坐标和y坐标构造SM2点

        如果x和y都是None，则表示无穷远点O
        """
        assert (x is None and y is None) or (0 <= x < ECC_P and 0 <= y < ECC_P)
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
                _lambda_numerator = p_add(p_mul(3, p_pow(self._x, 2)), ECC_A)  # x ** 2 * 3 + a
                _lambda_denominator = p_mul(2, self._y)  # 2 * y
                _lambda = p_div(_lambda_numerator, _lambda_denominator)

                x = p_minus(p_pow(_lambda, 2), p_mul(2, self._x))  # lambda ** 2 - 2 * x
                y = p_minus(p_mul(_lambda, p_minus(self._x, x)), self._y)

                return SM2Point(x, y)
            if p_add(self._y, other._y) == 0:  # 互逆点相加结果为无穷远点O
                return SM2Point(None, None)

            raise ValueError(f"Impossible condition: {self} + {other}")
        else:    # 非互逆不同点相加规则，GB/T 32918.1-2016 3.2.3.1 d) (P4)
            _lambda_numerator = p_minus(other._y, self._y)  # y2 - y1
            _lambda_denominator = p_minus(other._x, self._x)  # x2 - x1
            _lambda = p_div(_lambda_numerator, _lambda_denominator)
            x = p_minus(p_pow(_lambda, 2), p_add(self._x, other._x))   # lambda ** 2 - x1 - x2
            y = p_minus(p_mul(_lambda, p_minus(self._x, x)), self._y)  # lambda * (x1 - x3) - y1
            return SM2Point(x, y)

    def __mul__(self, k: int) -> 'SM2Point':
        """SM2点的整数倍"""
        res = SM2Point(None, None)
        next_pow = self

        mask = 1
        for r in range(ECC_LEN * 8):
            if k & mask != 0:
                res += next_pow
            mask <<= 1
            next_pow += next_pow
        return res

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
            if len(octets) != 2 * ECC_LEN + 1:
                raise ValueError(f"SM2点未压缩格式长度{len(octets)}不符合标准，应当为{2 * ECC_LEN + 1}")
            x = int.from_bytes(octets[1:ECC_LEN + 1], byteorder='big')
            y = int.from_bytes(octets[ECC_LEN + 1:], byteorder='big')
            return SM2Point(x, y)
        elif pc == 0x02 or pc == 0x03:
            y_p = 0x00 if pc == 0x02 else 0x01
            if len(octets) != ECC_LEN + 1:
                raise ValueError(f"SM2点压缩格式长度{len(octets)}不符合标准，应当为{ECC_LEN + 1}")
            x = int.from_bytes(octets[1:], byteorder='big')
            y_pow = p_adds(p_pow(x, 3), p_mul(ECC_A, x), ECC_B)  # GB/T 32918.1-2016 A.5.2
            y = p_sqrt(y_pow)

            if y & 0x01 == y_p:
                return SM2Point(x, y)
            else:
                return SM2Point(x, ECC_P - y)
        elif pc == 0x06 or pc == 0x07:
            y_p = 0x00 if pc == 0x06 else 0x01
            y = int.from_bytes(octets[ECC_LEN + 1:], byteorder='big')
            if len(octets) != 2 * ECC_LEN + 1:
                raise ValueError(f"SM2点混合格式长度{len(octets)}不符合标准，应当为{2 * ECC_LEN + 1}")
            x = int.from_bytes(octets[1:], byteorder='big')
            ry_pow = p_adds(p_pow(x, 3), p_mul(ECC_A, x), ECC_B)
            ry = p_sqrt(ry_pow)

            if ry & 0x01 == y_p:
                ry = ECC_P - ry
            if ry != y:
                raise ValueError("SM2点混合格式中存储的y值与x值和pc值恢复出的不一致")

        else:
            raise ValueError(f"SM2点的字节串表示PC值错误（{pc:02x}）")

    def __repr__(self):
        """SM2点的显示表示"""
        if self.is_zero_point():
            return "Point: O"
        return f'Point(x={self.x_octets.hex()}, y={self.y_octets.hex()})'


POINT_G = SM2Point(ECC_X, ECC_Y)  # SM2曲线的基点G

_POINT_G_EXPONENT_2_VALUES = []  # 基点G的2的幂倍列表，用于快速计算公钥


def _init_quick_mul_g_point():
    """初始化基点G的2的幂倍列表，用于快速计算公钥"""
    global _POINT_G_EXPONENT_2_VALUES
    if len(_POINT_G_EXPONENT_2_VALUES) == 0:
        _gbv = POINT_G
        for i in range(ECC_LEN * 8):
            _POINT_G_EXPONENT_2_VALUES.append(_gbv)
            _gbv += _gbv

    # for i in range(ECC_LEN * 8):
    #     assert G_POINT_BIT_VALUES[i]  == G_POINT * (1 << i)


def quick_mul_g_point(n: int) -> 'SM2Point':
    """快速计算基点G的方法"""
    _init_quick_mul_g_point()
    global _POINT_G_EXPONENT_2_VALUES
    p = SM2Point(None, None)
    mask = 1
    for i in range(ECC_LEN * 8):
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
    buffer.extend(_i2b(ECC_A))
    buffer.extend(_i2b(ECC_B))
    buffer.extend(_i2b(ECC_X))
    buffer.extend(_i2b(ECC_Y))
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
        return SM2Point.repr_uncompressed(self._point).hex().upper()

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
        if len(signature) != 2 * ECC_LEN:
            raise ValueError("签名数据长度错误（{}），请检查是否包含了额外的数据头或其他格式".format(len(signature)))
        r = int.from_bytes(signature[0:ECC_LEN], byteorder='big')
        logger.debug("r=%s", signature[0:ECC_LEN].hex())
        s = int.from_bytes(signature[ECC_LEN:], byteorder='big')
        logger.debug("s=%s", signature[ECC_LEN:].hex())
        buffer = bytearray(generator_z(self._point, uid))
        buffer.extend(message)
        e = int.from_bytes(sm3_hash(buffer), byteorder='big', signed=False)
        t = (r + s) % ECC_N  # Prove: t == (k + r) / (1 + d)
        if t == 0:
            return False

        pr = POINT_G * s + self._point * t    # Prove: pr == [k]G
        logger.debug("[k]G=%s", pr)
        vr = (e + pr.x) % ECC_N
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
            k = secrets.randbelow(ECC_N - 1) + 1
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
        assert secret is None or 0 < secret < ECC_N - 1
        self._secret = secrets.randbelow(ECC_N - 2) + 1 if secret is None else secret
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
        return int.to_bytes(self._secret, length=ECC_LEN, byteorder='big')

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
            k = secrets.randbelow(ECC_N - 1) + 1
            p = POINT_G * k
            logger.debug('[k]G=%s', p)
            r = (e + p.x) % ECC_N
            if r == 0 or r + k == ECC_N:
                continue
            logger.debug("r=%s", _i2h(r))
            s = (inverse_mod_prime(ECC_N, 1 + self._secret) * (k - r * self._secret) % ECC_N) % ECC_N
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
            pivot_1 = 2 * ECC_LEN + 1
            pivot_2 = pivot_1 + 32
            c1 = cipher_text[0:pivot_1]
            c3 = cipher_text[pivot_1:pivot_2]
            c2 = cipher_text[pivot_2:]
        elif mode == 'C1C2C3':
            pivot_1 = 2 * ECC_LEN + 1
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
