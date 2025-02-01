from unittest import TestCase
from asn1util import *
from gmutil import *

from os.path import join, abspath, pardir


class CertificateException(Exception):

    def __init__(self, *args):
        super().__init__(*args)


class InDevelopmentTestCase(TestCase):
    def test_dev_xts(self):
        cert_file = abspath(join(__file__, pardir, 'x509samples', 'sm2.oca.der'))
        with open(cert_file, 'rb') as cf:
            cert_data = cf.read()

        cert_t, cert_l, cert_v = read_next_tlv(cert_data)

        total_len = len(cert_t) + len(cert_l) + len(cert_v)

        if total_len < len(cert_data):
            raise CertificateException('格式错误：数字证书格式外有冗余数据'
                                       '/Redundant data besides certificate data.')

        cert_elements = asn1_decode(cert_v)

        if len(cert_elements) != 3:
            raise CertificateException('格式错误：Certificate的元素数不为3'
                                       '/"Certificate" does NOT contain 3 elements.')
        tbsCertificate, signatureAlgorithm, signatureValue = cert_elements

        # 解析signatureAlgorithm域
        if signatureAlgorithm.tag != TAG_Sequence:
            raise CertificateException('格式错误：signatureAlgorithm项不是SEQUENCE类型')

        sig_alg_items = asn1_decode(signatureAlgorithm.value_octets)
        print(sig_alg_items)

        if sig_alg_items[0].tag != TAG_ObjectIdentifier:
            raise CertificateException('格式错误：algorithm项不是OBJECT IDENTIFIER类型')
        algorithm: ASN1ObjectIdentifier = sig_alg_items[0]
        print(algorithm.oid_string,
              OBJECT_IDENTIFIERS[algorithm.oid_string]
              if algorithm.oid_string in OBJECT_IDENTIFIERS else 'N/A')
        parameters = sig_alg_items[1]

        # 解析signatureValue域
        if signatureValue.tag != TAG_BitString:
            raise CertificateException('格式错误：signatureValue项不是BITSTRING类型')

    def test_sm2_opt(self):
        print(POINT_G * 2)
        g2x, g2y = jacobian_ecc_point_add(POINT_G.x, POINT_G.y, POINT_G.x, POINT_G.y, SM2_P, SM2_A, SM2_B)
        G2 = SM2Point(g2x, g2y)
        print(G2)

        print(POINT_G * 3)
        g3x, g3y = jacobian_ecc_point_add(POINT_G.x, POINT_G.y, g2x, g2y, SM2_P, SM2_A, SM2_B)
        G3 = SM2Point(g3x, g3y)
        print(G3)


