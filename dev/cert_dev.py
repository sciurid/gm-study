from pkgutil import resolve_name
from unittest import TestCase
from asn1util import *
from gmutil import *
from oid_query import query_oid

from os.path import join, abspath, pardir


class CertificateException(Exception):

    def __init__(self, *args):
        super().__init__(*args)


def retrieve_element(element: ASN1DataType, expected_tags: Optional[Sequence[Tag]],
                     field_name: str, optional=False, default_value=False):
    if expected_tags is None:
        return element
    if element.tag in expected_tags:
        return element
    else:
        if optional or default_value:
            return None
        else:
            raise CertificateException(f'格式错误：{field_name}项类型不匹配')

def resolve_algorithm_identifier(element: ASN1DataType):
    algorithm = retrieve_element(element.value[0], (TAG_ObjectIdentifier, ), 'Algorithm')
    parameters = retrieve_element(element.value[1], None, 'Parameters')
    return algorithm.oid_string, parameters.value


SM2_WITH_SM3 = '1.2.156.10197.1.501'
SHA256_WITH_RSA = '1.2.840.113549.1.1.11'


class GMT0015Certificate:
    def __init__(self):
        self.tbs_certificate_data = None
        self.signature_algorithm_data = None
        self.signature_value_data = None

        self.version_data = None
        self.serial_number_data = None
        self.signature_data = None
        self.issuer_data = None
        self.validity_data = None
        self.subject_data = None
        self.subject_public_key_info_data = None


    @staticmethod
    def resolve_name(name):
        rdn_str = []
        for rdn in name:
            rdn = retrieve_element(rdn, (TAG_Set,), 'RelativeDistinguishedName')
            atv_str = []
            for atv in rdn.value:
                atv = retrieve_element(atv, (TAG_Sequence,), 'AttributeTypeAndValue')
                type = retrieve_element(atv.value[0], (TAG_ObjectIdentifier,), 'AttributeType')
                value = retrieve_element(atv.value[1],
                                         (TAG_PrintableString, TAG_UniversalString, TAG_BMPString, TAG_UTF8String,),
                                         'AttributeValue')
                oid_name = query_oid(type.oid_string)['name']
                if oid_name is None:
                    oid_name = type.oid_string
                atv_str.append(f'{oid_name}={value.value}')
            rdn_str.append(', '.join(atv_str))
        return ';'.join(rdn_str)

    @property
    def version(self):
        vd = retrieve_element(self.version_data.value[0],(TAG_Integer, ), "Version")
        return vd.value

    @property
    def serial_number(self):
        return self.serial_number_data.value

    @property
    def signature(self):
        return resolve_algorithm_identifier(self.signature_data)

    @property
    def signature_algorithm(self):
        return resolve_algorithm_identifier(self.signature_algorithm_data)

    @property
    def signature_value(self):
        return self.signature_value_data.value

    @property
    def subject_public_key_info(self):
        alg_element = retrieve_element(self.subject_public_key_info_data.value[0], (TAG_Sequence, ), 'Algorithm')
        alg = resolve_algorithm_identifier(alg_element)
        sbj_pub_key = retrieve_element(self.subject_public_key_info_data.value[1], (TAG_BitString, ), 'SubjectPublicKey')
        return alg, sbj_pub_key

    @property
    def issuer(self) -> str:
        return GMT0015Certificate.resolve_name(self.issuer_data.value)

    @property
    def subject(self) -> str:
        return GMT0015Certificate.resolve_name(self.subject_data.value)

    @property
    def validity(self):
        not_before = retrieve_element(self.validity_data.value[0], (TAG_UTCTime, TAG_GeneralizedTime,), 'NotBefore')
        not_after = retrieve_element(self.validity_data.value[1], (TAG_UTCTime, TAG_GeneralizedTime,), 'NotAfter')
        return not_before.value, not_after.value



    @staticmethod
    def load_der(cert_data: Union[bytes, bytearray, BinaryIO]):
        cert_structs = asn1_decode(cert_data)
        if len(cert_structs) != 1:
            raise CertificateException('格式错误：数字证书格式外有冗余数据'
                                       '/Redundant data besides certificate data.')

        cert_struct = cert_structs[0]
        if len(cert_struct.value) != 3:
            raise CertificateException('格式错误：Certificate的元素数不为3'
                                       '/"Certificate" does NOT contain 3 elements.')

        certificate = GMT0015Certificate()

        tbs_certificate, signature_algorithm, signature_value = cert_struct.value
        certificate.tbs_certificate_data = tbs_certificate
        certificate.signature_algorithm_data = signature_algorithm
        certificate.signature_value_data = signature_value

        # 解析TBSCertificate结构
        certificate.version_data = retrieve_element(tbs_certificate.value[0], None, 'Version', default_value=True)
        if certificate.version_data is not None and len(certificate.version_data.value) != 1:
            raise CertificateException('格式错误：Version版本号')
        certificate.serial_number_data = retrieve_element(tbs_certificate.value[1], (TAG_Integer,), 'Serial Number')
        certificate.signature_data = retrieve_element(tbs_certificate.value[2], (TAG_Sequence,), 'Signature')
        certificate.issuer_data = retrieve_element(tbs_certificate.value[3], (TAG_Sequence,), 'Issuer')
        certificate.validity_data = retrieve_element(tbs_certificate.value[4], (TAG_Sequence,), 'Validity')
        certificate.subject_data = retrieve_element(tbs_certificate.value[5], (TAG_Sequence,), 'Subject')
        certificate.subject_public_key_info_data = retrieve_element(tbs_certificate.value[6], (TAG_Sequence,), 'SubjectPublicKeyInfo')
        next_index = 7
        certificate.issuer_unique_id = retrieve_element(tbs_certificate.value[next_index], (TAG_BitString,), 'IssuerUniqueID',
                                            optional=True)
        if certificate.issuer_unique_id is not None:
            next_index += 1
        certificate.subject_unique_id = retrieve_element(tbs_certificate.value[next_index], (TAG_BitString,), 'SubjectUniqueID',
                                             optional=True)
        if certificate.subject_unique_id is not None:
            next_index += 1
        certificate.extensions = retrieve_element(tbs_certificate.value[next_index], None, 'Extensions',
                                      optional=True)
        if certificate.extensions is not None:
            next_index += 1

        if next_index != len(tbs_certificate.value):
            raise CertificateException('格式错误：TBSCertificate结尾有冗余内容')

        return certificate



class CertificateTestCase(TestCase):
    def test_dev_xts(self):
        for filename in ('sm2.rca.der', 'sm2.oca.der', 'chenqiang.me.cer'):
            cert_file = abspath(join(__file__, pardir, 'x509samples', filename))
            print(filename + " " + "=" * 30)
            with open(cert_file, 'rb') as cf:
                certificate = GMT0015Certificate.load_der(cf)

            print(certificate.version)
            print(certificate.serial_number)
            print(certificate.signature)
            print(certificate.issuer)
            print(certificate.subject)
            print(certificate.subject_public_key_info[0])
            print(certificate.subject_public_key_info[1].value[0].hex())
            print(certificate.validity)

            print()
            print(certificate.signature_algorithm)
            print(certificate.signature_value[0].hex())

            print()


    def test_signature(self):
        cert_file = abspath(join(__file__, pardir, 'x509samples', 'sm2.rca.der'))
        with open(cert_file, 'rb') as cf:
            root_ca = GMT0015Certificate.load_der(cf)

        pub_key = SM2PublicKey(SM2Point.from_bytes(root_ca.subject_public_key_info[1].value[0]))

        sig_seq = asn1_decode(root_ca.signature_value[0])[0]
        r = sig_seq.value[0].value.to_bytes(length=32, byteorder='big', signed=False)
        s = sig_seq.value[1].value.to_bytes(length=32, byteorder='big', signed=False)

        print(pub_key.verify(root_ca.tbs_certificate_data.octets, r + s))

        cert_file = abspath(join(__file__, pardir, 'x509samples', 'sm2.oca.der'))
        with open(cert_file, 'rb') as cf:
            middle_ca = GMT0015Certificate.load_der(cf)

        sig_seq = asn1_decode(middle_ca.signature_value[0])[0]
        r = sig_seq.value[0].value.to_bytes(length=32, byteorder='big', signed=False)
        s = sig_seq.value[1].value.to_bytes(length=32, byteorder='big', signed=False)
        print(pub_key.verify(middle_ca.tbs_certificate_data.octets, r + s))















