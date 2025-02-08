import itertools
from typing import Optional, Sequence, Literal, cast
from asn1util import *
import os
import base64
from os.path import abspath, join, dirname, realpath
import logging

from .sm3 import sm3_hash
from .sm2 import SM2PublicKey

logger = logging.getLogger(__name__)

class CertificateException(Exception):

    def __init__(self, *args):
        super().__init__(*args)


def _retrieve_element(element: ASN1DataType, expected_tags: Optional[Sequence[Tag]],
                      field_name: str, optional_default=False):
    """尝试匹配ASN.1元素及期望的类型"""
    if expected_tags is None:
        return element
    if element.tag in expected_tags:
        return element
    else:
        if optional_default:
            return None
        else:
            raise CertificateException(f'格式错误：{field_name}项类型不匹配')


def _retrieve_explict_element(element: ASN1DataType, expected_tags: Optional[Sequence[Tag]],
                              field_name: str, optional_default=False):
    """尝试匹配EXPLICIT包装的ASN.1元素及期望的类型"""
    wrapper = _retrieve_element(element, None, field_name, optional_default)
    if wrapper is None:
        return None, None
    else:
        if len(wrapper.value) != 1:
            raise CertificateException(f'格式错误：EXPLICIT域中{wrapper.tag}内元素不唯一')
        return wrapper, _retrieve_element(wrapper.value[0], expected_tags, field_name)


def _retrieve_sequence(elements: Sequence[ASN1DataType], definition: Sequence, field_name: str):
    """使用Sequence类型定义尝试逐项匹配ASN.1元素列表"""
    ind = 0
    res = []
    len_ele = len(elements)
    len_def = len(definition)
    for tag, fn, od in definition:
        if ind == len_ele:
            break
        ni = _retrieve_element(elements[ind], tag, fn, od)
        res.append(ni)
        if ni is not None:
            ind += 1

    if ind != len_ele:
        raise CertificateException('格式错误：扩展项A{}'.format(field_name))
    for _ in range(ind, len_def):
        res.append(None)
    return res


OID_NAMES = {
    "2.5.4.6": 'C',
    "2.5.4.10": 'O',
    "2.5.4.11": 'OU',
    "2.5.4.3": 'CN',
    "2.5.4.8": 'ST',
    "2.5.4.7": 'L'
}

def _resolve_name(name_field: ASN1Sequence):
    """将名称Name域提取为结构化列表"""
    rdns = []
    for rdn in name_field.value:
        rdn = _retrieve_element(rdn, (TAG_Set,), 'RelativeDistinguishedName')
        atvs = []
        for atv in rdn.value:
            atv = _retrieve_element(atv, (TAG_Sequence,), 'AttributeTypeAndValue')
            atr_type = cast(ASN1ObjectIdentifier,
                            _retrieve_element(atv.value[0], (TAG_ObjectIdentifier,), 'AttributeType'))
            atr_value = _retrieve_element(atv.value[1],
                                          (TAG_PrintableString, TAG_UniversalString, TAG_BMPString, TAG_UTF8String,),
                                         'AttributeValue')
            atvs.append((OID_NAMES[atr_type.oid_string], atr_type.oid_string, atr_value.value))
        rdns.append(atvs)
    return rdns


def _display_name(name_field: ASN1Sequence):
    """将名称Name域转化为可显示的字符串"""
    rdns = _resolve_name(name_field)
    return ';'.join([','.join([f'{atv[0]}={atv[2]}' for atv in rdn]) for rdn in rdns])


OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
OID_SHA256_WITH_RSA_ENCRYPTION = '1.2.840.113549.1.1.11'

OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
OID_SM2_ENCRYPTION = '1.2.156.10197.1.301'
OID_SM3_WITH_SM2_ENCRYPTION = '1.2.156.10197.1.501'


def _resolve_algorithm_identifier(element: ASN1DataType) -> Literal['SM3_WITH_SM2', 'SM2', 'SHA256_WITH_RSA', 'RSA']:
    """解析签名算法或公钥算法"""
    algorithm = cast(ASN1ObjectIdentifier,
                     _retrieve_element(element.value[0], (TAG_ObjectIdentifier,), 'Algorithm'))
    if len(element.value) > 1:
        parameters = _retrieve_element(element.value[1], None, 'Parameters')
    else:
        parameters = None

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

KEY_USAGE_DIGITAL_SIGNATURE = 0X01
KEY_USAGE_NON_REPUDIATION = 0x02
KEY_USAGE_KEY_ENCIPHERMENT = 0x04
KEY_USAGE_DATA_ENCIPHERMENT = 0x08
KEY_USAGE_KEY_AGREEMENT = 0x10
KEY_USAGE_KEY_CERT_SIGN = 0x20
KEY_USAGE_CRL_SIGN = 0x40
KEY_USAGE_ENCIPHER_ONLY = 0x80
KEY_USAGE_DECIPHER_ONLY = 0x100


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

        self._raw_octets = None

    def __eq__(self, other):
        if other is None:
            return False
        else:
            return self._raw_octets == other._raw_octets

    @property
    def version(self):
        """版本号"""
        vd = _retrieve_element(self._version_obj.value[0], (TAG_Integer,), "Version")
        return vd.value

    @property
    def serial_number(self):
        return self._serial_number_obj.value

    @property
    def signature(self):
        return _resolve_algorithm_identifier(self._signature_obj)

    @property
    def signature_algorithm(self):
        return _resolve_algorithm_identifier(self._signature_algorithm_obj)

    @property
    def signature_value(self):
        return self._signature_value_obj.value

    @property
    def tbs_certificate(self):
        return self._tbs_certificate_obj.octets

    @property
    def subject_public_key_info(self):
        alg_element = _retrieve_element(self._subject_public_key_info_obj.value[0], (TAG_Sequence,), 'Algorithm')
        alg = _resolve_algorithm_identifier(alg_element)
        sbj_pub_key = _retrieve_element(self._subject_public_key_info_obj.value[1], (TAG_BitString,), 'SubjectPublicKey')
        return alg, sbj_pub_key.value

    @property
    def issuer(self) -> str:
        return _display_name(self._issuer_obj)

    @property
    def subject(self) -> str:
        return _display_name(self._subject_obj)

    @property
    def validity(self):
        not_before = _retrieve_element(self._validity_obj.value[0], (TAG_UTCTime, TAG_GeneralizedTime,), 'NotBefore')
        not_after = _retrieve_element(self._validity_obj.value[1], (TAG_UTCTime, TAG_GeneralizedTime,), 'NotAfter')
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
    def authority_key_identifier(self) -> Tuple[Optional[bytes], Optional[List[str]], Optional[int], bool]:
        """颁发机构密钥标识符 AuthorityKeyIdentifier

        :return: 三元组分别为KeyIdentifier, AuthorityCertIssuer, AuthorityCertSerialNumber
        """
        aki_item = self.get_extension(OID_AUTHORITY_KEY_IDENTIFIER)
        if aki_item is None:
            return None, None, None, False
        seq = ASN1Sequence.from_bytes(aki_item[2])
        dfn = (((TAG_AuthorityKeyIdentifier, ), 'KeyIdentifier', False),
               ((TAG_Sequence, ), 'AuthorityCertIssuer', False),
               ((TAG_Integer, ), 'AuthorityCertSerialNumber', False))
        res = _retrieve_sequence(seq.value, dfn, 'AuthorityKeyIdentifier')

        return (res[0].value if res[0] else None,
                [e.value for e in res[1].value] if res[1] else None,
                res[2].value if res[2] else None,
                aki_item[1])

    @property
    def subject_key_identifier(self) -> Tuple[Optional[bytes], bool]:
        """主体密钥标识符 SubjectKeyIdentifier"""
        ski_item = self.get_extension(OID_SUBJECT_KEY_IDENTIFIER)
        if ski_item is None:
            return None, None
        ski = ASN1OctetString.from_bytes(ski_item[2])
        return ski.value, ski_item[1]

    @property
    def key_usage(self) -> Tuple[Optional[int], bool]:
        """密钥用法 KeyUsage"""
        ku_item = self.get_extension(OID_KEY_USAGE)
        if ku_item is None:
            return None, False
        ku = ASN1BitString.from_bytes(ku_item[2])
        return (int.from_bytes(ku.value, byteorder='big', signed=False)
                & ((1 << (len(ku.value) * 8 - ku.unused_bit_length)) - 1)), ku_item[1]

    @property
    def extended_key_usage(self) -> Tuple[Optional[List[str]], bool]:
        """扩展密钥用途"""
        eku_item = self.get_extension(OID_EXTENDED_KEY_USAGE)
        if eku_item is None:
            return None, False
        eku = ASN1Sequence.from_bytes(eku_item[2])
        return [cast(ASN1ObjectIdentifier, k_).oid_string
                for k_ in [_retrieve_element(k, (TAG_ObjectIdentifier,), 'KeyPurposeId')
                           for k in eku.value]], eku_item[1]

    @property
    def basic_constraints(self) -> Tuple[Optional[bool], Optional[int], bool]:
        """基本限制"""
        bc_item = self.get_extension(OID_BASIC_CONSTRAINTS)
        if bc_item is None:
            return None, None, False
        seq = ASN1Sequence.from_bytes(bc_item[2])
        dfn = (((TAG_Boolean,), 'CA', False),
               ((TAG_Integer,), 'PathLenConstraint', False))
        res = _retrieve_sequence(seq.value, dfn, 'BasicConstraints')
        return res[0].value if res[0] else None, res[1].value if res[1] else None, bc_item[1]


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

        _, cert._version_obj = _retrieve_explict_element(tbs_certificate.value[0], (TAG_Integer,), 'Version', True)
        cert._serial_number_obj = _retrieve_element(tbs_certificate.value[1], (TAG_Integer,), 'Serial Number')
        cert._signature_obj = _retrieve_element(tbs_certificate.value[2], (TAG_Sequence,), 'Signature')
        cert._issuer_obj = _retrieve_element(tbs_certificate.value[3], (TAG_Sequence,), 'Issuer')
        cert._validity_obj = _retrieve_element(tbs_certificate.value[4], (TAG_Sequence,), 'Validity')
        cert._subject_obj = _retrieve_element(tbs_certificate.value[5], (TAG_Sequence,), 'Subject')
        cert._subject_public_key_info_obj = _retrieve_element(tbs_certificate.value[6], (TAG_Sequence,), 'SubjectPublicKeyInfo')
        next_index = 7
        cert._issuer_unique_id_obj = _retrieve_element(tbs_certificate.value[next_index], (TAG_BitString,), 'IssuerUniqueID', True)
        if cert.issuer_unique_id is not None:
            next_index += 1
        cert._subject_unique_id_obj = _retrieve_element(tbs_certificate.value[next_index], (TAG_BitString,), 'SubjectUniqueID', True)
        if cert._subject_unique_id_obj is not None:
            next_index += 1


        _, cert._extensions_obj = _retrieve_explict_element(tbs_certificate.value[next_index], (TAG_Sequence,), 'Extensions', True)
        if cert._extensions_obj is not None:
            next_index += 1
            # 解析扩展项结构

            cert._extensions = []
            cert._extension_map = {}
            for ext_item in cert._extensions_obj.value:
                if not (1 < len(ext_item.value) < 4):
                    raise CertificateException('格式错误：扩展项Extension元素数错误')
                extn_id_obj = cast(ASN1ObjectIdentifier,
                                   _retrieve_element(ext_item.value[0], (TAG_ObjectIdentifier,), 'ExtensionID'))
                extn_id = extn_id_obj.oid_string

                ext_index = 1
                critical_obj = _retrieve_element(ext_item.value[ext_index], (TAG_Boolean,), 'Critical', True)
                if critical_obj is not None:
                    ext_index += 1
                extn_value_obj = _retrieve_element(ext_item.value[ext_index], (TAG_OctetString,), 'ExtensionValue')
                ext_item_record = (extn_id, critical_obj.value if critical_obj else False, extn_value_obj.value)
                cert._extensions.append(ext_item_record)
                cert._extension_map[extn_id] = ext_item_record

        if next_index != len(tbs_certificate.value):
            raise CertificateException('格式错误：TBSCertificate结尾有冗余内容')

        return cert

ROOT_CA_CERTS = []

def load_root_ca_certs():
    root_ca_dir = abspath(join(dirname(realpath(__file__)), 'NRCAC'))

    for filename in os.listdir(root_ca_dir):
        if filename.endswith('.cer'):
            with open(join(root_ca_dir, filename), 'r') as f:
                ca_der_data = base64.b64decode(f.read())
                ca_cert = Certificate.load_certificate(ca_der_data)
                logger.info(f'{"=" * 10}ROOT CA: {filename} {"=" * 10}')
                logger.info(f'Subject: {ca_cert.subject}')
                logger.info(f'Serial Number: {ca_cert.serial_number}')
                logger.info(f'Not Before: {ca_cert.validity[0].isoformat()}')
                logger.info(f'Not After: {ca_cert.validity[1].isoformat()}')
                logger.info(f'Public Key Info: {ca_cert.subject_public_key_info[0]}')

            ROOT_CA_CERTS.append(ca_cert)


load_root_ca_certs()


def verify_cert(subject_cert: Certificate, issuer_cert: Certificate):
    issuer_alg = issuer_cert.subject_public_key_info[0]
    sig_alg = subject_cert.signature_algorithm

    if issuer_alg == 'SM2':
        if sig_alg != 'SM3_WITH_SM2':
            return False, f'颁发者密钥算法{issuer_alg}与主体签名算法{sig_alg}不一致'

        pub_key = SM2PublicKey.from_bytes(issuer_cert.subject_public_key_info[1])
        sig_seq = ASN1Sequence.from_bytes(subject_cert.signature_value)
        r = sig_seq.value[0].value.to_bytes(32, byteorder='big')
        s = sig_seq.value[1].value.to_bytes(32, byteorder='big')
        verified = pub_key.verify(subject_cert.tbs_certificate, r + s)
        if not verified:
            return False, (f'证书SM2签名验证失败：主体{subject_cert.subject} {subject_cert.serial_number}，'
                           f'颁发者{issuer_cert.subject} {issuer_cert.serial_number}')
        return True, '验证通过'

    raise CertificateException(f'不支持的签名算法{issuer_alg}')


def verify_cert_chain(cert_chain: Sequence[Certificate], additional_cas: Optional[List[Certificate]] = None) -> Tuple[bool, str]:
    if len(cert_chain) == 0:
        return False, '证书链为空'

    verified: List[Certificate] = []
    verified.extend(ROOT_CA_CERTS)
    if additional_cas:
        verified.extend(additional_cas)

    unknown = [c for c in cert_chain if c not in verified]

    ski_map = {}
    for cert in verified:
        if cert.subject_key_identifier[0]:
            ski_map[cert.subject_key_identifier[0]] = [cert, True]
        else:
            raise CertificateException(f'证书{cert.subject}({cert.serial_number})没有SubjectKeyIdentifier项')

    for cert in unknown:
        if cert.subject_key_identifier[0]:
            ski_map[cert.subject_key_identifier[0]] = [cert, False]
        else:
            raise CertificateException(f'证书{cert.subject}({cert.serial_number})没有SubjectKeyIdentifier项')

    pairs = []
    for cert in unknown:
        if aki := cert.authority_key_identifier[0]:
            if aki in ski_map:
                pairs.append((cert, ski_map[aki][0]))
            else:
                return False, f'证书{cert.subject}({cert.serial_number})未找到颁发者证书'

    while pairs:
        for pair in pairs:
            subject, issuer = pair[0], pair[1]
            sski = subject.subject_key_identifier[0]
            iski = issuer.subject_key_identifier[0]
            if (not ski_map[sski][1]) and ski_map[iski][1]:
                res, msg = verify_cert(subject, issuer)
                if res:
                    pairs.remove(pair)
                    break
                else:
                    return False, msg
        else:
            return False, '证书链中存在无法验证的证书: {}'.format('|'.join(p[0].subject for p in pairs))

    return True, '验证通过'





