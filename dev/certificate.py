from typing import Optional, Sequence, Literal
from asn1util import *
from .oid_util import query_oid

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

OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
OID_SHA256_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.11'

OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
OID_SM2_ENCRYPTION = '1.2.156.10197.1.301'
OID_SM3_WITH_SM2_ENCRYPTION = '1.2.156.10197.1.501'






def resolve_algorithm_identifier(element: ASN1DataType) -> Literal['SM3_WITH_SM2', 'SM2']:
    algorithm = retrieve_element(element.value[0], (TAG_ObjectIdentifier, ), 'Algorithm')
    parameters = retrieve_element(element.value[1], None, 'Parameters')

    if algorithm.oid_string == OID_SM3_WITH_SM2_ENCRYPTION:
        return 'SM3_WITH_SM2'
    if algorithm.oid_string == OID_SM2_ENCRYPTION:
        return 'SM2'
    if algorithm.oid_string == OID_EC_PUBLIC_KEY and parameters.oid_string == OID_SM2_ENCRYPTION:
        return 'SM2'

    raise CertificateException('格式错误：不支持的算法{} {}'.format(
        algorithm.oid_string, parameters.oid_string if parameters else 'N/A'))


class Certificate:
    def __init__(self):
        self._tbs_certificate_obj = None
        self._signature_algorithm_obj = None
        self._signature_value_obj = None

        self._version_obj = None
        self._serial_number_obj = None
        self._signature_obj = None
        self._issuer_obj = None
        self._validity_obj = None
        self._subject_obj = None
        self._subject_public_key_info_obj = None

        self._issuer_unique_id = None
        self._subject_unique_id = None
        self._extensions = None


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
                atv_str.append(f'{type.oid_string}={value.value}')
            rdn_str.append(', '.join(atv_str))
        return ';'.join(rdn_str)

    @property
    def version(self):
        vd = retrieve_element(self._version_obj.value[0],(TAG_Integer, ), "Version")
        return vd.value

    @property
    def serial_number(self):
        return self._serial_number_obj.value

    @property
    def signature(self):
        return resolve_algorithm_identifier(self._signature_obj)

    @property
    def signature_algorithm(self):
        return resolve_algorithm_identifier(self._signature_algorithm_obj)

    @property
    def signature_value(self):
        return self._signature_value_obj.value[0]

    @property
    def tbs_certificate(self):
        return self._tbs_certificate_obj.octets

    @property
    def subject_public_key_info(self):
        alg_element = retrieve_element(self._subject_public_key_info_obj.value[0], (TAG_Sequence, ), 'Algorithm')
        alg = resolve_algorithm_identifier(alg_element)
        sbj_pub_key = retrieve_element(self._subject_public_key_info_obj.value[1], (TAG_BitString, ), 'SubjectPublicKey')
        return alg, sbj_pub_key.value[0]

    @property
    def issuer(self) -> str:
        return Certificate.resolve_name(self._issuer_obj.value)

    @property
    def subject(self) -> str:
        return Certificate.resolve_name(self._subject_obj.value)

    @property
    def validity(self):
        not_before = retrieve_element(self._validity_obj.value[0], (TAG_UTCTime, TAG_GeneralizedTime,), 'NotBefore')
        not_after = retrieve_element(self._validity_obj.value[1], (TAG_UTCTime, TAG_GeneralizedTime,), 'NotAfter')
        return not_before.value, not_after.value

    @property
    def issuer_unique_id(self):
        if self._issuer_unique_id is None:
            return None
        return self._issuer_unique_id.value[0]

    @property
    def subject_unique_id(self):
        if self._subject_unique_id is None:
            return None
        return self._subject_unique_id.value

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

        certificate = Certificate()

        tbs_certificate, signature_algorithm, signature_value = cert_struct.value
        certificate._tbs_certificate_obj = tbs_certificate
        certificate._signature_algorithm_obj = signature_algorithm
        certificate._signature_value_obj = signature_value

        # 解析TBSCertificate结构
        certificate._version_obj = retrieve_element(tbs_certificate.value[0], None, 'Version', default_value=True)
        if certificate._version_obj is not None and len(certificate._version_obj.value) != 1:
            raise CertificateException('格式错误：Version版本号')
        certificate._serial_number_obj = retrieve_element(tbs_certificate.value[1], (TAG_Integer,), 'Serial Number')
        certificate._signature_obj = retrieve_element(tbs_certificate.value[2], (TAG_Sequence,), 'Signature')
        certificate._issuer_obj = retrieve_element(tbs_certificate.value[3], (TAG_Sequence,), 'Issuer')
        certificate._validity_obj = retrieve_element(tbs_certificate.value[4], (TAG_Sequence,), 'Validity')
        certificate._subject_obj = retrieve_element(tbs_certificate.value[5], (TAG_Sequence,), 'Subject')
        certificate._subject_public_key_info_obj = retrieve_element(tbs_certificate.value[6], (TAG_Sequence,), 'SubjectPublicKeyInfo')
        next_index = 7
        certificate._issuer_unique_id = retrieve_element(tbs_certificate.value[next_index], (TAG_BitString,), 'IssuerUniqueID',
                                            optional=True)
        if certificate.issuer_unique_id is not None:
            next_index += 1
        certificate._subject_unique_id = retrieve_element(tbs_certificate.value[next_index], (TAG_BitString,), 'SubjectUniqueID',
                                             optional=True)
        if certificate._subject_unique_id is not None:
            next_index += 1
        certificate._extensions = retrieve_element(tbs_certificate.value[next_index], None, 'Extensions',
                                      optional=True)
        if certificate._extensions is not None:
            next_index += 1

        if next_index != len(tbs_certificate.value):
            raise CertificateException('格式错误：TBSCertificate结尾有冗余内容')

        return certificate