from gmutil import gmac
from unittest import TestCase


class MACTestCase(TestCase):
    """ 测试向量验证

    《信息技术 安全技术 消息鉴别码 第3部分：采用泛杂凑函数的机制》（GB/T 15852.3-2019） 附录A
    """
    def test_gmac_sample(self):
        mine = gmac(key=b'\x00' * 16, message=b'', n=b'\x00' * 12)
        ref = bytes.fromhex('23 2f 0c fe 30 8b 49 ea 6f c8 82 29 b5 dc 85 8d')
        self.assertEqual(mine, ref)

        mine = gmac(
            key=bytes.fromhex('fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08'),
            message=bytes.fromhex('fe ed fa ce de ad be ef fe ed fa ce de ad be ef'),
            n=bytes.fromhex('ca fe ba be fa ce db ad de ca f8 88')
        )

        ref = bytes.fromhex('9d 63 25 70 f9 30 64 26 4a 20 91 8e 30 81 b4 cd')
        self.assertEqual(ref, mine)

        mine = gmac(
            key=bytes.fromhex('fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08'),
            message=bytes.fromhex('fe ed fa ce de ad be ef fe ed fa ce de ad be ef'
                                  'ab ad da d2 42 83 1e c2 21 77 74 24 4b 72 21 b7'),
            n=bytes.fromhex('ca fe ba be fa ce db ad de ca f8 88')
        )

        ref = bytes.fromhex('1e ea eb 66 9e 96 bd 05 9b d9 92 91 23 03 0e 78')
        self.assertEqual(ref, mine)


