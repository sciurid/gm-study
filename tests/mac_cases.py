from gmutil import sm4_gmac, sm3_hash, sm3_hmac
from unittest import TestCase
from io import StringIO


class MACTestCase(TestCase):
    """ 测试向量验证

    《信息技术 安全技术 消息鉴别码 第3部分：采用泛杂凑函数的机制》（GB/T 15852.3-2019） 附录A
    """
    def test_gmac_sample(self):
        mine = sm4_gmac(key=b'\x00' * 16, message=b'', n=b'\x00' * 12)
        ref = bytes.fromhex('23 2f 0c fe 30 8b 49 ea 6f c8 82 29 b5 dc 85 8d')
        self.assertEqual(mine, ref)

        mine = sm4_gmac(
            key=bytes.fromhex('fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08'),
            message=bytes.fromhex('fe ed fa ce de ad be ef fe ed fa ce de ad be ef'),
            n=bytes.fromhex('ca fe ba be fa ce db ad de ca f8 88')
        )

        ref = bytes.fromhex('9d 63 25 70 f9 30 64 26 4a 20 91 8e 30 81 b4 cd')
        self.assertEqual(ref, mine)

        mine = sm4_gmac(
            key=bytes.fromhex('fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08'),
            message=bytes.fromhex('fe ed fa ce de ad be ef fe ed fa ce de ad be ef'
                                  'ab ad da d2 42 83 1e c2 21 77 74 24 4b 72 21 b7'),
            n=bytes.fromhex('ca fe ba be fa ce db ad de ca f8 88')
        )

        ref = bytes.fromhex('1e ea eb 66 9e 96 bd 05 9b d9 92 91 23 03 0e 78')
        self.assertEqual(ref, mine)


    def test_hmac_sample(self):
        # GB/T 15852.2-2024 C.2
        buffer = StringIO()
        for i in range(1000000):
            buffer.write('a')

        messages = (
            '', 'a', 'abc', 'message digest',
            'abcdefghijklmnopqrstuvwxyz', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
            '1234567890' * 8,
            buffer.getvalue()
        )

        key_1 = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
        key_2 = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')

        # 密钥 1 的 MAC 值
        mac_key1 = [
            "C8E4E95012EB3D449B5DD0691947986E469E08A3506BB55CCB94A96EBFADA654",
            "5FD9F7568A24C438F14B7A22E799B0689FE053ABB76D316202E3C9D10E9EEBE2",
            "0933617A88D312F6F9FB4B5F200E31A64D655E92F7FA2A43F55DFEEB8AB6788D",
            "9C9A22E8B5797B82CFF9BABA56893CC1D75811C334D198F3AF43401740B824F7",
            "A51CE58C52AE29EDD66A53E6AAF0745BF4FEDBDE899973B2D817290E646DF87E",
            "DC813339153491AD81477754EB3DF00DBB3CC3E6A69F9CACCE737DB7E61342FF",
            "BCA6FA751AECAC5BA3AC49963F6A58F7C2293C6E6923802BC52117A741A49FEE",
            "25E034DF9A3AC81599C233440CA6F68F38CA5166438BFA620210EC2F59880C0D",
            "34DB1B0452359EA54DA16932E42A662BE88C19C5AD4FE9073867C05A92752024"
        ]

        # 密钥 2 的 MAC 值
        mac_key2 = [
            "F14B797B559216B73D3816ADFB790250AF3F21198A1AE867123762BB63A00945",
            "5BD1836B97C74F88A77BC309E77A269481F53BE9D5C4CE1E40B1C50FE574762E",
            "28D8A61BE67D8BF7652C4EDA7092B612F88BE62184F55005C57DDF076E764199",
            "E0ACCC4DA77E77D135F17F5CA1EE3E600DAB444FC23ADD6F7E6A54E1B34B26BC",
            "429D9030B1D992AD8198E01C13141C2859A913D69DE00CCE9E4A60F00BF276CB",
            "AAB294F80562AB234E6226BF7FC3B03F839C7759E60F69735B7E99E50EB94A24",
            "08F457B37E5E062AFAFB24DE8D48B92246F1788BAAD4D7B3D11E5F627E33A0D3",
            "9F85C779D718A33BDEC2D6E0C1F280FE6A8C12FF2521530A44D168DD4080BC14",
            "ED3057AB0DB1E826240FCF8E8760C3DB9338E9AABDAD8B11BB0C040D73E74441"
        ]


        for ind, message in enumerate(messages):
            # print(message)
            hk1 = sm3_hmac(key_1, message.encode())
            hk2 = sm3_hmac(key_2, message.encode())
            # print(xor_on_bytes(hk1, bytes.fromhex(mac_key1[ind])).hex())
            self.assertEqual(hk1.hex(), mac_key1[ind].lower())
            self.assertEqual(hk2.hex(), mac_key2[ind].lower())





