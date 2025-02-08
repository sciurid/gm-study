from dataclasses import dataclass

from calculation import *
from typing import List, Optional

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
            self._cache[0] = mul_mod_prime(SM2_P, self.x, self.x)
        return self._cache[0]

    @property
    def pow_x_3(self):
        if self._cache[1] is None:
            self._cache[1] = mul_mod_prime(SM2_P, self.pow_x_2, self.x)
        return self._cache[1]

    @property
    def pow_y_2(self):
        if self._cache[2] is None:
            self._cache[2] = mul_mod_prime(SM2_P, self.y, self.y)
        return self._cache[2]

    @property
    def pow_y_4(self):
        if self._cache[3] is None:
            y_2 = self.pow_y_2
            self._cache[3] = mul_mod_prime(SM2_P, y_2, y_2)
        return self._cache[3]

    @property
    def inv_z_1(self):
        if self._cache[4] is None:
            self._cache[4] = inverse_mod_prime(SM2_P, self.z)
        return self._cache[4]

    @property
    def inv_z_2(self):
        if self._cache[5] is None:
            self._cache[5] = mul_mod_prime(SM2_P, self.inv_z_1, self.inv_z_1)
        return self._cache[5]

    @property
    def inv_z_3(self):
        if self._cache[6] is None:
            self._cache[6] = mul_mod_prime(SM2_P, self.inv_z_2, self.inv_z_1)
        return self._cache[6]

    @property
    def pow_z_2(self):
        if self._cache[7] is None:
            self._cache[7] = mul_mod_prime(SM2_P, self.z, self.z)
        return self._cache[7]

    @property
    def pow_z_3(self):
        if self._cache[8] is None:
            self._cache[8] = mul_mod_prime(SM2_P, self.pow_z_2, self.z)
        return self._cache[8]

    @property
    def pow_z_4(self):
        if self._cache[9] is None:
            self._cache[9] = mul_mod_prime(SM2_P, self.pow_z_2, self.pow_z_2)
        return self._cache[9]

    @property
    def pow_z_6(self):
        if self._cache[10] is None:
            self._cache[10] = mul_mod_prime(SM2_P, self.pow_z_3, self.pow_z_3)
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
            self._norm_x = mul_mod_prime(SM2_P, self._x, self._cache.inv_z_2)
        return self._norm_x

    @property
    def x_octets(self):
        return None if self.x is None else self.x.to_bytes(SM2_P_BYTE_LEN, byteorder='big', signed=False)

    @property
    def y(self):
        if self._z == 0:
            return None
        elif self._norm_y is None:
            self._norm_y = mul_mod_prime(SM2_P, self._y, self._cache.inv_z_3)
        return self._norm_y

    @property
    def y_octets(self):
        return None if self.y is None else self.y.to_bytes(SM2_P_BYTE_LEN, byteorder='big', signed=False)

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
            right = adds_mod_prime(SM2_P, self._cache.pow_x_3,
                                   mul_mod_prime(SM2_P, SM2_A, self._x), SM2_B)
        else:
            right = adds_mod_prime(SM2_P,self._cache.pow_x_3,
                                   muls_mod_prime(SM2_P, SM2_A, self._x, self._cache.pow_z_4),
                                   mul_mod_prime(SM2_P, SM2_B, self._cache.pow_z_6))
        return left == right

    @staticmethod
    def check_same_or_reverse_point(p1: 'SM2Point_Jacobian', p2: 'SM2Point_Jacobian'):
        """检验不为无穷远的两个点是否相同或互为逆元"""
        lx = mul_mod_prime(SM2_P, p1._x, p2._cache.pow_z_2)
        rx = mul_mod_prime(SM2_P, p2._x, p1._cache.pow_z_2)
        if lx != rx:
            return 0
        ly = mul_mod_prime(SM2_P, p1._y, p2._cache.pow_z_3)
        ry = mul_mod_prime(SM2_P, p2._y, p1._cache.pow_z_3)
        if ly == ry:
            return 1
        elif mul_mod_prime(SM2_P, ly, ry) == 0:
            return -1
        else:
            raise ValueError('相同X的两点Y不相同也不相反')


    def __eq__(self, other: 'SM2Point_Jacobian'):
        return SM2Point_Jacobian.check_same_or_reverse_point(self, other) == 1

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
            l1 = add_mod_prime(SM2_P, mul_mod_prime(SM2_P, 3, p1._cache.pow_x_2),
                               mul_mod_prime(SM2_P, SM2_A, p1._cache.pow_z_4))
            l2 = muls_mod_prime(SM2_P, 4, p1._x, p1._cache.pow_y_2)
            l3 = mul_mod_prime(SM2_P, 8, p1._cache.pow_y_4)

            x3 = minus_mod_prime(SM2_P, mul_mod_prime(SM2_P, l1, l1), muls_mod_prime(SM2_P, 2, l2))
            y3 = minus_mod_prime(SM2_P, mul_mod_prime(SM2_P, l1, minus_mod_prime(SM2_P, l2, x3)), l3)
            z3 = muls_mod_prime(SM2_P, 2, p1._y, p1._z)
            return SM2Point_Jacobian(x3, y3, z3)
        else:
            l1 = mul_mod_prime(SM2_P, p1._x, p2._cache.pow_z_2)
            l2 = mul_mod_prime(SM2_P, p2._x, p1._cache.pow_z_2)
            l3 = minus_mod_prime(SM2_P, l1, l2)
            l4 = mul_mod_prime(SM2_P, p1._y, p2._cache.pow_z_3)
            l5 = mul_mod_prime(SM2_P, p2._y, p1._cache.pow_z_3)
            l6 = minus_mod_prime(SM2_P, l4, l5)
            l7 = add_mod_prime(SM2_P, l1, l2)

            l3_2 = mul_mod_prime(SM2_P, l3, l3)
            l3_3 = mul_mod_prime(SM2_P, l3_2, l3)

            x3 = minus_mod_prime(SM2_P, mul_mod_prime(SM2_P,l6, l6), mul_mod_prime(SM2_P, l7, l3_2))

            y3_p1 = minus_mod_prime(SM2_P, mul_mod_prime(SM2_P, l1, l3_2), x3)
            y3_p2 = mul_mod_prime(SM2_P, l4, l3_3)
            y3 = minus_mod_prime(SM2_P, mul_mod_prime(SM2_P, l6, y3_p1), y3_p2)
            z3 = muls_mod_prime(SM2_P, p1._z, p2._z, l3)
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
        pow_y_2 = adds_mod_prime(SM2_P, pow_mod_prime(SM2_P, x, 3),
                                 muls_mod_prime(SM2_P, SM2_A, x), SM2_B)
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


class PointG(SM2Point_Jacobian):
    def __init__(self):
        super().__init__(SM2_X, SM2_Y)
        PointG.init_exp_list()

    _POWER_OF_TWO_EXP = None
    @classmethod
    def init_exp_list(cls):
        if cls._POWER_OF_TWO_EXP is None:
            cls._POWER_OF_TWO_EXP = []
            exp_g = PointG()
            for i in range(SM2_P_BYTE_LEN * 8):
                cls._POWER_OF_TWO_EXP.append(exp_g)
                exp_g += exp_g
                exp_g = exp_g.normalize()


SM2_POINT_G = PointG()

g1 = SM2Point_Jacobian(SM2_X, SM2_Y, 1)
g2 = SM2Point_Jacobian(mul_mod_prime(SM2_P, SM2_X, 4),
                       mul_mod_prime(SM2_P, SM2_Y, 8),
                       2)

assert g1 == g2
assert g2 == g1

g3 = g1 + g2
g4 = g1 + g3
g5 = g2 + g3
assert g4 == g5
assert g4 == SM2_POINT_G * 3
