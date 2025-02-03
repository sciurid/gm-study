import os
import re
import base64
from io import StringIO
from os.path import abspath, join, pardir, realpath

from asn1util import ASN1Sequence
from dev.certificate import Certificate, CertificateException
from gmutil import SM2PublicKey

_PEM_BEGIN_BOUNDARY_PATTERN = re.compile(r'-+BEGIN (\w+)-+')
_PEM_END_BOUNDARY_PATTERN = re.compile(r'-+END (\w+)-+')

class PemFileFormatException(Exception):
    def __init__(self, *args):
        super().__init__(*args)


def load_cn_root_ca_certs():
    root_ca_dir = abspath(join(realpath(__file__), pardir, 'NRCAC'))
    root_cas = []
    for filename in os.listdir(root_ca_dir):
        if filename.endswith('.cer'):
            with open(join(root_ca_dir, filename), 'r') as f:
                der_data = base64.b64decode(f.read())
                ca_cert = Certificate.load_certificate(der_data)
                print(ca_cert.serial_number)
                print(ca_cert.subject)
            root_cas.append(ca_cert)

    return root_cas


def load_pem(file_path):
    name = None
    buffer = None
    result = []
    with open(file_path, 'r', encoding='iso-8859-1') as f:
        for line in f:
            line = line.strip()
            if m := _PEM_BEGIN_BOUNDARY_PATTERN.match(line):
                if name is not None:
                    raise PemFileFormatException(name, buffer)
                else:
                    name = m.group(1)
                    buffer = StringIO()
                    continue
            if m := _PEM_END_BOUNDARY_PATTERN.match(line):
                if name is None or name != m.group(1):
                    raise PemFileFormatException()
                else:
                    data = base64.standard_b64decode(buffer.getvalue())
                    result.append((name, data))
                    name = None
                    buffer = None
                    continue
            if len(line) == 0 or line[0] == '#':
                continue

            buffer.write(line)
    return result


root_cas = load_cn_root_ca_certs()

cert_file = abspath(join(__file__, pardir, 'x509samples', 'ebssec.boc.cn.crt'))
certs = load_pem(cert_file)

parent = None
for cert_data in reversed(certs):
    cert = Certificate.load_certificate(cert_data[1])
    if parent is None:  # Root
        print('-' * 20)
        print(cert.serial_number)
        print(cert.subject, cert.subject_unique_id)
        print(cert.issuer, cert.issuer_unique_id)
        if cert.subject_public_key_info[0] == 'SM2':
            pub_key = SM2PublicKey.from_bytes(cert.subject_public_key_info[1])
            sig_seq = ASN1Sequence.from_bytes(cert.signature_value)
            r = sig_seq.value[0].value.to_bytes(32, byteorder='big')
            s = sig_seq.value[1].value.to_bytes(32, byteorder='big')
            verified = pub_key.verify(cert.tbs_certificate, r + s)
            if not verified:
                raise CertificateException()

            print('验证通过')
            parent = cert
        else:
            raise CertificateException()
    else:
        print('-' * 20)
        print(cert.serial_number)
        print(cert.subject, cert.subject_unique_id)
        print(cert.issuer, cert.issuer_unique_id)
        print(cert.authority_key_identifier)
        for ext_item in cert.extensions:
            print(ext_item[0], ext_item[1], ext_item[2].hex())
        if cert.subject_public_key_info[0] == 'SM2':
            issuer_pub_key = SM2PublicKey.from_bytes(parent.subject_public_key_info[1])
            sig_seq = ASN1Sequence.from_bytes(cert.signature_value)
            r = sig_seq.value[0].value.to_bytes(32, byteorder='big')
            s = sig_seq.value[1].value.to_bytes(32, byteorder='big')
            verified = issuer_pub_key.verify(cert.tbs_certificate, r + s)
            if not verified:
                raise CertificateException()
            print('验证通过')
            parent = cert
        else:
            raise CertificateException()

