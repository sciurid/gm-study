from typing import Optional, Tuple, List
import secrets
from .sm3hash import sm3_hash, sm3_kdf
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


def p_inv(n: int) -> int:
    return inverse_mod_prime(SM2_P, n)


def p_div(a: int, b: int) -> int:
    return (a * p_inv(b)) % SM2_P


def p_sqrt(n: int) -> Optional[int]:
    return square_root_mod_prime(SM2_P, n)


def _i2h(n: int) -> Optional[str]:
    """将整数值转化为长度为ECC的HEX字符串，用于点坐标的显示"""
    return _i2b(n).hex()


def _i2b(n: int):
    """将整数值转化为长度为ECC的字节串，用于点坐标的转换"""
    return int.to_bytes(n, length=SM2_P_BYTE_LEN, byteorder="big")


"""
========================================================================================================================
SM2椭圆曲线上点的Jacobian仿射坐标系实现

未进行计算优化，仅用于学习参考。
========================================================================================================================
"""


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
        if self._x is not None and not SM2Point.on_curve(x, y):  # 检验是否在椭圆曲线上
            raise ValueError(f"点{_i2h(x)} {_i2h(y)}不在SM2椭圆曲线上")

    @staticmethod
    def on_curve(x: int, y: int) -> int:
        """检查点(x,y)是否在SM2椭圆曲线上"""
        left = (y ** 2) % SM2_P
        right = (x ** 3 + SM2_A * x + SM2_B) % SM2_P
        return left == right

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
    def from_bytes(octets: Union[bytes, bytearray, memoryview]) -> 'SM2Point':
        """从字节串表示中恢复SM2点
        GB/T 32918.1-2016 4.2.10
        """

        def calc_y(_x: int) -> int:
            """根据SM2椭圆曲线上点的x计算对应的y

            GB/T 32918.1-2016 A.5.2
            """
            return p_sqrt((_x ** 3 + SM2_A * _x + SM2_B) % SM2_P)

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
            y_pow = p_adds(p_pow(x, 3), p_mul(SM2_A, x), SM2_B)
            y = calc_y(x)

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
            ry = calc_y(x)

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

"""
========================================================================================================================
SM2椭圆曲线上点的Jacobian加重射影坐标系实现

采取了尽可能少计算求反、保留计算中间值等方式降低计算量。实际使用于SM2的公钥、私钥和密钥交换中。
========================================================================================================================
"""


class _Calculation_Cache:
    """用于加速计算的中间值缓存"""

    def __init__(self, x: int, y: int, z: int):
        self.x = x
        self.y = y
        self.z = z

        """
        0: pow x 2
        1: pow x 3
        2: pow y 2
        3: pow y 4
        4: inv z 1
        5: inv z 2
        6: inv z 3
        7: pow z 2
        8: pow z 3
        9: pow z 4
        10: pow z 6
        """
        self._cache: List[Optional[int]] = [None] * 11

    @property
    def pow_x_2(self):
        if self._cache[0] is None:
            self._cache[0] = p_mul(self.x, self.x)
        return self._cache[0]

    @property
    def pow_x_3(self):
        if self._cache[1] is None:
            self._cache[1] = p_mul(self.pow_x_2, self.x)
        return self._cache[1]

    @property
    def pow_y_2(self):
        if self._cache[2] is None:
            self._cache[2] = p_mul(self.y, self.y)
        return self._cache[2]

    @property
    def pow_y_4(self):
        if self._cache[3] is None:
            y_2 = self.pow_y_2
            self._cache[3] = p_mul(y_2, y_2)
        return self._cache[3]

    @property
    def inv_z_1(self):
        if self._cache[4] is None:
            self._cache[4] = p_inv(self.z)
        return self._cache[4]

    @property
    def inv_z_2(self):
        if self._cache[5] is None:
            self._cache[5] = p_mul(self.inv_z_1, self.inv_z_1)
        return self._cache[5]

    @property
    def inv_z_3(self):
        if self._cache[6] is None:
            self._cache[6] = p_mul(self.inv_z_2, self.inv_z_1)
        return self._cache[6]

    @property
    def pow_z_2(self):
        if self._cache[7] is None:
            self._cache[7] = p_mul(self.z, self.z)
        return self._cache[7]

    @property
    def pow_z_3(self):
        if self._cache[8] is None:
            self._cache[8] = p_mul(self.pow_z_2, self.z)
        return self._cache[8]

    @property
    def pow_z_4(self):
        if self._cache[9] is None:
            self._cache[9] = p_mul(self.pow_z_2, self.pow_z_2)
        return self._cache[9]

    @property
    def pow_z_6(self):
        if self._cache[10] is None:
            self._cache[10] = p_mul(self.pow_z_3, self.pow_z_3)
        return self._cache[10]


class SM2Point_Jacobian:
    def __init__(self, x: Optional[int], y: Optional[int], z: int = 1):
        assert 0 <= x < SM2_P
        assert 0 <= y < SM2_P
        assert 0 <= z < SM2_P
        assert (z == 0) == (x == y)  # z为0时表示无穷远点

        self._x = x
        self._y = y
        self._z = z
        self._cache = _Calculation_Cache(x, y, z)

        self._norm_x = None
        self._norm_y = None
        self._pow_two_exp = None
        assert self.on_curve()

    @property
    def infinite(self):
        return self._z == 0

    @property
    def x(self):
        if self._z == 0:
            return None
        elif self._norm_x is None:
            self._norm_x = p_mul(self._x, self._cache.inv_z_2)
        return self._norm_x

    @property
    def x_octets(self):
        return None if self.x is None else _i2b(self.x)

    @property
    def y(self):
        if self._z == 0:
            return None
        elif self._norm_y is None:
            self._norm_y = p_mul(self._y, self._cache.inv_z_3)
        return self._norm_y

    @property
    def y_octets(self):
        return None if self.y is None else _i2b(self.y)

    def normalize(self):
        if self._z == 0:
            return SM2Point_Jacobian(1, 1, 0)
        else:
            return SM2Point_Jacobian(self.x, self.y)

    def on_curve(self):
        if self._z == 0:
            return True

        left = self._cache.pow_y_2

        if self._z == 1:
            right = p_adds(self._cache.pow_x_3,
                           p_mul(SM2_A, self._x), SM2_B)
        else:
            right = p_adds(self._cache.pow_x_3,
                                   p_muls(SM2_A, self._x, self._cache.pow_z_4),
                                   p_mul(SM2_B, self._cache.pow_z_6))
        return left == right

    @staticmethod
    def check_same_or_reverse_point(p1: 'SM2Point_Jacobian', p2: 'SM2Point_Jacobian'):
        """检验不为无穷远的两个点是否相同或互为逆元"""
        lx = p_mul(p1._x, p2._cache.pow_z_2)
        rx = p_mul(p2._x, p1._cache.pow_z_2)
        if lx != rx:
            return 0
        ly = p_mul(p1._y, p2._cache.pow_z_3)
        ry = p_mul(p2._y, p1._cache.pow_z_3)
        if ly == ry:
            return 1
        elif p_mul(ly, ry) == 0:
            return -1
        else:
            raise ValueError('相同X的两点Y不相同也不相反')

    def __eq__(self, other: 'SM2Point_Jacobian'):
        return SM2Point_Jacobian.check_same_or_reverse_point(self, other) == 1

    def __repr__(self):
        """SM2点的显示表示"""
        if self.infinite:
            return "(INFINITE POINT)"
        return f'Point(x={self.x_octets.hex()}, y={self.y_octets.hex()})'

    @staticmethod
    def point_add(p1: 'SM2Point_Jacobian', p2: 'SM2Point_Jacobian'):
        if p1.infinite:
            return p2
        if p2.infinite:
            return p1

        sr = SM2Point_Jacobian.check_same_or_reverse_point(p1, p2)
        if sr == -1:
            return SM2Point_Jacobian(1, 1, 0)

        if sr == 1:
            l1 = p_add(p_mul(3, p1._cache.pow_x_2),
                       p_mul(SM2_A, p1._cache.pow_z_4))
            l2 = p_muls(4, p1._x, p1._cache.pow_y_2)
            l3 = p_mul(8, p1._cache.pow_y_4)

            x3 = p_minus(p_mul(l1, l1), p_muls(2, l2))
            y3 = p_minus(p_mul(l1, p_minus(l2, x3)), l3)
            z3 = p_muls(2, p1._y, p1._z)
            return SM2Point_Jacobian(x3, y3, z3)
        else:
            l1 = p_mul(p1._x, p2._cache.pow_z_2)
            l2 = p_mul(p2._x, p1._cache.pow_z_2)
            l3 = p_minus(l1, l2)
            l4 = p_mul(p1._y, p2._cache.pow_z_3)
            l5 = p_mul(p2._y, p1._cache.pow_z_3)
            l6 = p_minus(l4, l5)
            l7 = p_add(l1, l2)

            l3_2 = p_mul(l3, l3)
            l3_3 = p_mul(l3_2, l3)

            x3 = p_minus(p_mul(l6, l6), p_mul(l7, l3_2))

            y3_p1 = p_minus(p_mul(l1, l3_2), x3)
            y3_p2 = p_mul(l4, l3_3)
            y3 = p_minus(p_mul(l6, y3_p1), y3_p2)
            z3 = p_muls(p1._z, p2._z, l3)
            return SM2Point_Jacobian(x3, y3, z3)

    def __add__(self, other):
        return SM2Point_Jacobian.point_add(self, other)

    def __radd__(self, other):
        return SM2Point_Jacobian.point_add(other, self)

    def __mul__(self, k: int):
        """SM2点的整数倍，使用了二进制的快速计算方法，并缓存了2的整数次幂用于加速计算"""
        if self._pow_two_exp is None:
            self._pow_two_exp = []
            exp_p = self
            for r in range(SM2_P_BYTE_LEN * 8):
                self._pow_two_exp.append(exp_p)
                exp_p += exp_p
                exp_p = exp_p.normalize()

        res = SM2Point_Jacobian(1, 1, 0)
        mask = 1
        for r in range(SM2_P_BYTE_LEN * 8):
            if k & mask != 0:
                res += self._pow_two_exp[r]
            mask <<= 1
        return res

    def __rmul__(self, k: int):
        return self.__mul__(k)


class SM2PointRepr:
    @staticmethod
    def to_uncompressed(p: SM2Point_Jacobian) -> bytes:
        """SM2点的非压缩表示（04开头）
        GB/T 32918.1-2016 4.2.9 c)
        """
        buffer = bytearray()
        buffer.append(0x04)
        buffer.extend(p.x_octets)
        buffer.extend(p.y_octets)
        return bytes(buffer)

    @staticmethod
    def to_compressed(p: SM2Point_Jacobian) -> bytes:
        """SM2点的压缩表示（02或03开头）
        GB/T 32918.1-2016 4.2.9 c)
        """
        buffer = bytearray()
        y_p = p.y & 0x01
        buffer.append(0x02 if y_p == 0 else 0x03)
        buffer.extend(p.x_octets)
        return bytes(buffer)

    @staticmethod
    def to_hybrid(p: SM2Point_Jacobian) -> bytes:
        """SM2点的混合表示（06或07开头）
        GB/T 32918.1-2016 4.2.9 d)
        """
        buffer = bytearray()
        y_p = p.y & 0x01
        buffer.append(0x06 if y_p == 0 else 0x07)
        buffer.extend(p.x_octets)
        buffer.extend(p.y_octets)
        return bytes(buffer)

    @staticmethod
    def calc_y(x: int) -> int:
        """通过x计算SM2曲线上对应的其中一个y值

        # GB/T 32918.1-2016 A.5.2
        """
        pow_y_2 = p_adds(p_pow(x, 3),
        p_muls(SM2_A, x), SM2_B)
        return square_root_mod_prime(SM2_P, pow_y_2)

    @staticmethod
    def from_bytes(octets: Union[bytes, bytearray, memoryview]) -> SM2Point_Jacobian:
        """从字节串表示中恢复SM2点
        GB/T 32918.1-2016 4.2.10
        """
        pc = octets[0]
        if pc == 0x04:
            if len(octets) != 2 * SM2_P_BYTE_LEN + 1:
                raise ValueError(f"SM2点未压缩格式长度{len(octets)}不符合标准，应当为{2 * SM2_P_BYTE_LEN + 1}")
            x = int.from_bytes(octets[1:SM2_P_BYTE_LEN + 1], byteorder='big', signed=False)
            y = int.from_bytes(octets[SM2_P_BYTE_LEN + 1:], byteorder='big', signed=False)
            return SM2Point_Jacobian(x, y)
        elif pc == 0x02 or pc == 0x03:
            y_p = 0x00 if pc == 0x02 else 0x01
            if len(octets) != SM2_P_BYTE_LEN + 1:
                raise ValueError(f"SM2点压缩格式长度{len(octets)}不符合标准，应当为{SM2_P_BYTE_LEN + 1}")
            x = int.from_bytes(octets[1:], byteorder='big', signed=False)
            y = SM2PointRepr.calc_y(x)
            if y & 0x01 != y_p:
                y = SM2_P - y
            return SM2Point_Jacobian(x, y)
        elif pc == 0x06 or pc == 0x07:
            y_p = 0x00 if pc == 0x06 else 0x01
            y = int.from_bytes(octets[SM2_P_BYTE_LEN + 1:], byteorder='big', signed=False)
            if len(octets) != 2 * SM2_P_BYTE_LEN + 1:
                raise ValueError(f"SM2点混合格式长度{len(octets)}不符合标准，应当为{2 * SM2_P_BYTE_LEN + 1}")
            x = int.from_bytes(octets[1:], byteorder='big', signed=False)
            ry = SM2PointRepr.calc_y(x)
            if ry & 0x01 != y_p:
                ry = SM2_P - ry
            if ry != y:
                raise ValueError("SM2点混合格式中存储的y值与x值和pc值恢复出的不一致")
            return SM2Point_Jacobian(x, y)
        else:
            raise ValueError(f"SM2点的字节串表示PC值错误（{pc:02x}）")


SM2_POINT_G = SM2Point_Jacobian(SM2_X, SM2_Y, 1)
"""SM2椭圆曲线的基点G"""

"""
========================================================================================================================
SM2公钥和私钥实现部分
========================================================================================================================
"""

DEFAULT_USER_ID = '1234567812345678'.encode()
"""用户身份ID的默认值为0x1234567812345678（GM/T 0009-2023 7 用户身份标识ID的默认值）"""


def generator_z(p: SM2Point_Jacobian, uid: bytes) -> bytes:
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
    def __init__(self, point: SM2Point_Jacobian):
        self._point = point

    @property
    def point(self):
        return self._point

    def __eq__(self, other: 'SM2PublicKey'):
        return self._point == other._point

    def __repr__(self):
        return '({},{})'.format(self._point.x_octets.hex().upper(), self._point.y_octets.hex().upper())

    @property
    def octets(self) -> bytes:
        return SM2PointRepr.to_uncompressed(self._point)

    @staticmethod
    def from_bytes(octets: Union[bytes, bytearray, memoryview]):
        return SM2PublicKey(SM2PointRepr.from_bytes(octets))

    @staticmethod
    def from_coordinates(x: Optional[Union[int, bytes]], y: Optional[Union[int, bytes]]):
        if isinstance(x, bytes):
            x = int.from_bytes(x, byteorder='big', signed=False)
        if isinstance(y, bytes):
            y = int.from_bytes(y, byteorder='big', signed=False)
        return SM2PublicKey(SM2Point_Jacobian(x, y))

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

        pr = SM2_POINT_G * s + self._point * t  # Prove: pr == [k]G
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

            p1 = SM2_POINT_G * k
            c1 = SM2PointRepr.to_uncompressed(p1)
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
        """SM2私钥的整数值（秘密）"""
        return self._secret

    def get_public_key(self) -> SM2PublicKey:
        if self._pub_key is None:
            self._pub_key = SM2PublicKey(SM2_POINT_G * self._secret)
        return self._pub_key

    @property
    def public_key(self) -> SM2PublicKey:
        return self.get_public_key()

    @property
    def point(self):
        return self.get_public_key().point

    def to_bytes(self) -> bytes:
        """SM2私钥的字节表示（秘密）"""
        return int.to_bytes(self._secret, length=SM2_P_BYTE_LEN, byteorder='big')

    @staticmethod
    def from_bytes(octets: bytes) -> 'SM2PrivateKey':
        return SM2PrivateKey(int.from_bytes(octets, byteorder='big', signed=False))

    def __eq__(self, other: 'SM2PrivateKey') -> bool:
        return self.value == other.value

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
            p = SM2_POINT_G * k
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
        self._point_r = SM2_POINT_G * r

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
        if self._point_uv.infinite:
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

    @staticmethod
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
        s_1 = SM2KeyExchange.calculate_sab(False, self._point_uv, self._own_z, self._other_z,
                                           self.point_r, self._other_point_r)
        if s_1 != s_b:
            raise ValueError("密钥确认步骤（A9）失败：S_B={}, S_1={}".format(s_b.hex(), s_1.hex()))

    def send_3(self) -> Tuple[bytes]:
        s_a = SM2KeyExchange.calculate_sab(True, self._point_uv, self._own_z, self._other_z,
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
        self._s_b = SM2KeyExchange.calculate_sab(False, self._point_uv, self._other_z, self._own_z,
                                                 self._other_point_r, self.point_r)

    def send_2(self):
        return self._public_key, self._point_r, self._uid, self._s_b

    def receive_3(self, s_a: bytes):
        s_2 = SM2KeyExchange.calculate_sab(True, self._point_uv, self._other_z, self._own_z,
                                           self._other_point_r, self.point_r)
        if s_2 != s_a:
            raise ValueError("密钥确认步骤（A9）失败：S_B={}, S_1={}".format(s_a.hex(), s_2.hex()))
