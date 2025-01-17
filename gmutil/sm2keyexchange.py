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
    def __init__(self, private_key: Optional[SM2PrivateKey] = None, uid: bytes = DEFAULT_USER_ID):
        self._private_key = SM2PrivateKey() if private_key is None else private_key
        self._public_key = self._private_key.get_public_key()
        self._uid = uid

        """GB/T 32918.3-2016 6.1 A1-A2/B1-B2"""
        r = secrets.randbelow(ECC_N - 1) + 1
        self._point_r = POINT_G * r

        x_bar = _x_bar(self._point_r.x)
        self._t = (self._private_key.value + x_bar * r) % ECC_N

    @property
    def public_key(self) -> SM2PublicKey:
        return self._public_key

    @property
    def uid(self):
        return self._uid

    @property
    def point_r(self):
        """GB/T 32918.3-2016 6.1 A3/B3
        用于发给对方的R_A/R_B点
        """
        return self._point_r

    def receive(self, public_key_other: SM2PublicKey, point_r_other: SM2Point,
                uid_other: bytes, k_byte_len: int, party_a: bool = False):
        """收到对方发来的R_A/R_B点之后的处理
        :param public_key_other: 对方的公钥
        :param point_r_other SM2Point 对方发来的点
        :param uid_other SM2Point 对方的用户身份ID
        :param k_byte_len 要交换的密钥长度
        :param party_a 是否为用户A（先发送点R的一方）
        """

        x_bar_other = _x_bar(point_r_other.x)
        point_v = (public_key_other.point + point_r_other * x_bar_other) * self._t
        if point_v.is_zero_point():
            raise ValueError("密钥协商协商失败：计算出点V为无穷远点")

        buffer = bytearray()
        buffer.extend(point_v.x_octets)
        buffer.extend(point_v.y_octets)
        if party_a:
            buffer.extend(self.public_key.generate_z(self.uid))
            buffer.extend(public_key_other.generate_z(uid_other))
        else:
            buffer.extend(public_key_other.generate_z(uid_other))
            buffer.extend(self.public_key.generate_z(self.uid))

        return sm3_kdf(buffer, k_byte_len)
