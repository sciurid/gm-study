from unittest import TestCase
from gmutil import *


class CertCases(TestCase):
    def test_verification(self):

        for filename in ('ebssec.boc.cn.crt', 'sm2-rsa.ihuandu.crt'):
            cert_file_path = join(dirname(realpath(__file__)), 'x509samples', filename)
            certs = PemFile.load(cert_file_path).items
            cert_chain = []
            for cert_data in certs:
                if cert_data[0] != 'CERTIFICATE':
                    raise PemFileFormatException('Pem文件中存在不是CERTIFICATE的部分：{cert_data[0]}')
                cert_chain.append(Certificate.load_certificate(cert_data[1]))

            res, message = verify_cert_chain(cert_chain)
            print(message)
            self.assertTrue(res)

    def test_cert_chain(self):
        filename = 'sm2-rsa.ihuandu.crt'
        filename = 'ebssec.boc.cn.crt'
        cert_file_path = join(dirname(realpath(__file__)), 'x509samples', filename)

        certs = PemFile.load(cert_file_path).items
        for cert_data in certs:
            if cert_data[0] != 'CERTIFICATE':
                raise PemFileFormatException('Pem文件中存在不是CERTIFICATE的部分：{cert_data[0]}')
            cert = Certificate.load_certificate(cert_data[1])
            print("=" * 20)
            print(cert.subject)
            print(cert.issuer)
            print(cert.serial_number)

            pub_key = SM2PublicKey.from_bytes(cert.subject_public_key_info[1])
            print("Pubkey    :", pub_key.octets.hex())
            print(cert._subject_public_key_info_obj.value[1].octets.hex())
            print("Identifier:", sm3_hash(pub_key.octets).hex())
            if cert.subject_key_identifier[0]:
                print("SKI       :", cert.subject_key_identifier[0].hex())
            if cert.authority_key_identifier[0]:
                print("AKI       :", cert.authority_key_identifier[0].hex())

