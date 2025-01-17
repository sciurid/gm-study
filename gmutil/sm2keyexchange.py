"""
GB/T 32918.3-2016规定的密钥交换协议
"""

from .calc import *
from .sm3 import *
from .sm2 import *
import secrets


w = ((ECC_N - 1).bit_length() + 1) // 2 - 1

def _x_bar(x: int) -> int:
    return (1 << w) + x & ((1 << w) - 1)


class SM2KeyExchange:
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
        r = secrets.randbelow(ECC_N - 1) + 1
        self._point_r = POINT_G * r

        # GB/T 32918.3-2016 6.1 A1-A2/B1-B2
        x_bar = _x_bar(self._point_r.x)
        self._t = (self._private_key.value + x_bar * r) % ECC_N

        # 在密钥计算阶段保存用于B8、A9、A10、B10步骤的数据
        self._exchanged_key = None
        self._other_z = None
        self._own_z = None
        self._point_uv = None
        self._other_point_r = None

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

    def calculate_key(self, party_a: bool, public_key_other: SM2PublicKey, point_r_other: SM2Point, uid_other: bytes) -> bytes:
        """根据对方发来的R_A/R_B点协商形成密钥

        :param party_a 是否为用户A（先发送点R的一方）
        :param public_key_other: 对方的公钥
        :param point_r_other SM2Point 对方发来的点
        :param uid_other SM2Point 对方的用户身份ID
        :return: bytes 协商形成的密钥
        """

        self._other_point_r = point_r_other
        x_bar_other = _x_bar(point_r_other.x)
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
        return (s_a, )


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


    def receive_1(self, k_byte_len: int, public_key_a: SM2PublicKey, point_r_a: SM2Point, uid_a: bytes) -> bytes:
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

