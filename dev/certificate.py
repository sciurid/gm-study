from typing import Optional, Sequence, Literal, cast
from collections import namedtuple
from asn1util import *


class CertificateException(Exception):

    def __init__(self, *args):
        super().__init__(*args)


def retrieve_element(element: ASN1DataType, expected_tags: Optional[Sequence[Tag]],
                     field_name: str, optional_default=False):
    if expected_tags is None:
        return element
    if element.tag in expected_tags:
        return element
    else:
        if optional_default:
            return None
        else:
            raise CertificateException(f'格式错误：{field_name}项类型不匹配')



def retrieve_explict_element(element: ASN1DataType, expected_tags: Optional[Sequence[Tag]],
                             field_name: str, optional_default=False):
    wrapper = retrieve_element(element, None, field_name, optional_default)
    if wrapper is None:
        return None, None
    else:
        if len(wrapper.value) != 1:
            raise CertificateException(f'格式错误：EXPLICIT域中{wrapper.tag}内元素不唯一')
        return wrapper, retrieve_element(wrapper.value[0], expected_tags, field_name)


OID_NAMES = {
    "2.5.4.6": 'C',
    "2.5.4.10": 'O',
    "2.5.4.11": 'OU',
    "2.5.4.3": 'CN',
    "2.5.4.8": 'ST',
    "2.5.4.7": 'L'
}

def resolve_name(name_field: ASN1Sequence):
    """将名称Name域提取为结构化列表"""
    rdns = []
    for rdn in name_field.value:
        rdn = retrieve_element(rdn, (TAG_Set,), 'RelativeDistinguishedName')
        atvs = []
        for atv in rdn.value:
            atv = retrieve_element(atv, (TAG_Sequence,), 'AttributeTypeAndValue')
            atr_type = cast(ASN1ObjectIdentifier,
                            retrieve_element(atv.value[0], (TAG_ObjectIdentifier,), 'AttributeType'))
            atr_value = retrieve_element(atv.value[1],
                                         (TAG_PrintableString, TAG_UniversalString, TAG_BMPString, TAG_UTF8String,),
                                         'AttributeValue')
            atvs.append((OID_NAMES[atr_type.oid_string], atr_type.oid_string, atr_value.value))
        rdns.append(atvs)
    return rdns


def display_name(name_field: ASN1Sequence):
    """将名称Name域转化为可显示的字符串"""
    rdns = resolve_name(name_field)
    return ';'.join([','.join([f'{atv[0]}={atv[2]}' for atv in rdn]) for rdn in rdns])


OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
OID_SHA256_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.11'

OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
OID_SM2_ENCRYPTION = '1.2.156.10197.1.301'
OID_SM3_WITH_SM2_ENCRYPTION = '1.2.156.10197.1.501'


def resolve_algorithm_identifier(element: ASN1DataType) -> Literal['SM3_WITH_SM2', 'SM2', 'SHA256_WITH_RSA', 'RSA']:
    """解析签名算法或公钥算法"""
    algorithm = cast(ASN1ObjectIdentifier,
                     retrieve_element(element.value[0], (TAG_ObjectIdentifier, ), 'Algorithm'))
    parameters = retrieve_element(element.value[1], None, 'Parameters')

    if algorithm.oid_string == OID_SM3_WITH_SM2_ENCRYPTION:
        return 'SM3_WITH_SM2'
    if algorithm.oid_string == OID_SM2_ENCRYPTION:
        return 'SM2'
    if algorithm.oid_string == OID_EC_PUBLIC_KEY and \
            cast(ASN1ObjectIdentifier, parameters).oid_string == OID_SM2_ENCRYPTION:
        return 'SM2'

    if algorithm.oid_string == OID_SHA256_WITH_RSA_ENCRYPTION:
        return 'SHA256_WITH_RSA'
    if algorithm.oid_string == OID_RSA_ENCRYPTION:
        return 'RSA'

    raise CertificateException('格式错误：不支持的算法{}'.format(algorithm.oid_string))


"""
2.5.29.1 - old Authority Key Identifier
2.5.29.2 - old Primary Key Attributes
2.5.29.3 - Certificate Policies
2.5.29.4 - Primary Key Usage Restriction
2.5.29.9 - Subject Directory Attributes
2.5.29.14 - Subject Key Identifier
2.5.29.15 - Key Usage
2.5.29.16 - Private Key Usage Period
2.5.29.17 - Subject Alternative Name
2.5.29.18 - Issuer Alternative Name
2.5.29.19 - Basic Constraints
2.5.29.20 - CRL Number
2.5.29.21 - Reason code
2.5.29.23 - Hold Instruction Code
2.5.29.24 - Invalidity Date
2.5.29.27 - Delta CRL indicator
2.5.29.28 - Issuing Distribution Point
2.5.29.29 - Certificate Issuer
2.5.29.30 - Name Constraints
2.5.29.31 - CRL Distribution Points
2.5.29.32 - Certificate Policies
2.5.29.33 - Policy Mappings
2.5.29.35 - Authority Key Identifier
2.5.29.36 - Policy Constraints
2.5.29.37 - Extended key usage
2.5.29.46 - FreshestCRL
2.5.29.54 - X.509 version 3 certificate extension Inhibit Any-policy
"""

# OID_OLD_AUTHORITY_KEY_IDENTIFIER = '2.5.29.1'
# OID_OLD_PRIMARY_KEY_ATTRIBUTES = '2.5.29.2'
# OID_CERTIFICATE_POLICIES = '2.5.29.3'
OID_PRIMARY_KEY_USAGE_RESTRICTION = '2.5.29.4'
OID_SUBJECT_DIRECTORY_ATTRIBUTES = '2.5.29.9'
OID_SUBJECT_KEY_IDENTIFIER = '2.5.29.14'
OID_KEY_USAGE = '2.5.29.15'
OID_PRIVATE_KEY_USAGE_PERIOD = '2.5.29.16'
OID_SUBJECT_ALTERNATIVE_NAME = '2.5.29.17'
OID_ISSUER_ALTERNATIVE_NAME = '2.5.29.18'
OID_BASIC_CONSTRAINTS = '2.5.29.19'
OID_CRL_NUMBER = '2.5.29.20'
OID_REASON_CODE = '2.5.29.21'
OID_HOLD_INSTRUCTION_CODE = '2.5.29.23'
OID_INVALIDITY_DATE = '2.5.29.24'
OID_DELTA_CRL_INDICATOR = '2.5.29.27'
OID_ISSUING_DISTRIBUTION_POINT = '2.5.29.28'
OID_CERTIFICATE_ISSUER = '2.5.29.29'
OID_NAME_CONSTRAINTS = '2.5.29.30'
OID_CRL_DISTRIBUTION_POINTS = '2.5.29.31'
OID_CERTIFICATE_POLICIES = '2.5.29.32'
OID_POLICY_MAPPINGS = '2.5.29.33'
OID_AUTHORITY_KEY_IDENTIFIER = '2.5.29.35'
OID_POLICY_CONSTRAINTS = '2.5.29.36'
OID_EXTENDED_KEY_USAGE = '2.5.29.37'
OID_FRESHESTCRL = '2.5.29.46'
OID_X_509_VERSION_3_CERTIFICATE_EXTENSION_INHIBIT_ANY_POLICY = '2.5.29.54'


TAG_AuthorityKeyIdentifier = Tag(b'\x80')


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

        self._issuer_unique_id_obj = None
        self._subject_unique_id_obj = None
        self._extensions_obj = None

        self._extensions = None
        self._extension_map = None

    @property
    def version(self):
        """版本号"""
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
        return self._signature_value_obj.value

    @property
    def tbs_certificate(self):
        return self._tbs_certificate_obj.octets

    @property
    def subject_public_key_info(self):
        alg_element = retrieve_element(self._subject_public_key_info_obj.value[0], (TAG_Sequence, ), 'Algorithm')
        alg = resolve_algorithm_identifier(alg_element)
        sbj_pub_key = retrieve_element(self._subject_public_key_info_obj.value[1], (TAG_BitString, ), 'SubjectPublicKey')
        return alg, sbj_pub_key.value

    @property
    def issuer(self) -> str:
        return display_name(self._issuer_obj)

    @property
    def subject(self) -> str:
        return display_name(self._subject_obj)

    @property
    def validity(self):
        not_before = retrieve_element(self._validity_obj.value[0], (TAG_UTCTime, TAG_GeneralizedTime,), 'NotBefore')
        not_after = retrieve_element(self._validity_obj.value[1], (TAG_UTCTime, TAG_GeneralizedTime,), 'NotAfter')
        return not_before.value, not_after.value

    @property
    def issuer_unique_id(self):
        if self._issuer_unique_id_obj is None:
            return None
        return self._issuer_unique_id_obj.value[0]

    @property
    def subject_unique_id(self):
        if self._subject_unique_id_obj is None:
            return None
        return self._subject_unique_id_obj.value

    @property
    def extensions(self):
        return self._extensions

    def get_extension(self, oid):
        return self._extension_map[oid] if oid in self._extension_map else None

    @property
    def authority_key_identifier(self):
        aki = self.get_extension(OID_AUTHORITY_KEY_IDENTIFIER)
        if aki is None:
            return None, None, None
        seq = ASN1Sequence.from_bytes(aki[2])

        ind = 0
        res = []
        for tag, fn in (((TAG_AuthorityKeyIdentifier, ), 'KeyIdentifier'),
                        ((TAG_Sequence, ), 'AuthorityCertIssuer'),
                        ((TAG_Integer, ), 'AuthorityCertSerialNumber')):
            if ind >= len(seq.value):
                break
            ni = retrieve_element(seq.value[ind], tag, fn, True)
            res.append(ni)
            if ni is not None:
                ind += 1

        if ind != len(seq.value):
            raise CertificateException('格式错误：扩展项AuthorityKeyIdentifier')
        for _ in range(ind, 3):
            res.append(None)

        return res[0], res[1], res[2]


    @staticmethod
    def load_certificate(der_data: Union[bytes, bytearray, BinaryIO]):
        cert_structs = asn1_decode(der_data)
        if len(cert_structs) != 1:
            raise CertificateException('格式错误：数字证书格式外有冗余数据'
                                       '/Redundant data besides certificate data.')

        cert_struct = cert_structs[0]
        if len(cert_struct.value) != 3:
            raise CertificateException('格式错误：Certificate的元素数不为3'
                                       '/"Certificate" does NOT contain 3 elements.')

        cert = Certificate()

        tbs_certificate, signature_algorithm, signature_value = cert_struct.value
        cert._tbs_certificate_obj = tbs_certificate
        cert._signature_algorithm_obj = signature_algorithm
        cert._signature_value_obj = signature_value

        # 解析TBSCertificate结构

        _, cert._version_obj = retrieve_explict_element(tbs_certificate.value[0], (TAG_Integer, ), 'Version', True)
        cert._serial_number_obj = retrieve_element(tbs_certificate.value[1], (TAG_Integer,), 'Serial Number')
        cert._signature_obj = retrieve_element(tbs_certificate.value[2], (TAG_Sequence,), 'Signature')
        cert._issuer_obj = retrieve_element(tbs_certificate.value[3], (TAG_Sequence,), 'Issuer')
        cert._validity_obj = retrieve_element(tbs_certificate.value[4], (TAG_Sequence,), 'Validity')
        cert._subject_obj = retrieve_element(tbs_certificate.value[5], (TAG_Sequence,), 'Subject')
        cert._subject_public_key_info_obj = retrieve_element(tbs_certificate.value[6], (TAG_Sequence,), 'SubjectPublicKeyInfo')
        next_index = 7
        cert._issuer_unique_id_obj = retrieve_element(tbs_certificate.value[next_index], (TAG_BitString,), 'IssuerUniqueID', True)
        if cert.issuer_unique_id is not None:
            next_index += 1
        cert._subject_unique_id_obj = retrieve_element(tbs_certificate.value[next_index], (TAG_BitString,), 'SubjectUniqueID', True)
        if cert._subject_unique_id_obj is not None:
            next_index += 1


        _, cert._extensions_obj = retrieve_explict_element(tbs_certificate.value[next_index], (TAG_Sequence,), 'Extensions', True)
        if cert._extensions_obj is not None:
            next_index += 1
            # 解析扩展项结构

            cert._extensions = []
            cert._extension_map = {}
            for ext_item in cert._extensions_obj.value:
                if not (1 < len(ext_item.value) < 4):
                    raise CertificateException('格式错误：扩展项Extension元素数不为3个')
                extn_id_obj = cast(ASN1ObjectIdentifier,
                                   retrieve_element(ext_item.value[0], (TAG_ObjectIdentifier,), 'ExtensionID'))
                extn_id = extn_id_obj.oid_string

                ext_index = 1
                critical_obj = retrieve_element(ext_item.value[ext_index], (TAG_Boolean,), 'Critical', True)
                if critical_obj is not None:
                    ext_index += 1
                extn_value_obj = retrieve_element(ext_item.value[ext_index], (TAG_OctetString,), 'ExtensionValue')
                ext_item_record = (extn_id, critical_obj.value if critical_obj else False, extn_value_obj.value)
                cert._extensions.append(ext_item_record)
                cert._extension_map[extn_id] = ext_item_record

        if next_index != len(tbs_certificate.value):
            raise CertificateException('格式错误：TBSCertificate结尾有冗余内容')

        return cert
