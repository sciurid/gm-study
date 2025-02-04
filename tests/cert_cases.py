from unittest import TestCase
from os.path import join, realpath, dirname
from gmutil import verify_cert_chain, PemFile, Certificate, CertificateException, PemFileFormatException

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
