from unittest import TestCase
from gmutil import *
from .certificate import *
from os.path import join, abspath, pardir


class CertificateTestCase(TestCase):
    def test_dev_xts(self):
        for filename in ('sm2.rca.der', 'sm2.oca.der', 'chenqiang.me.cer'):
            cert_file = abspath(join(__file__, pardir, 'x509samples', filename))
            print(filename + " " + "=" * 30)
            with open(cert_file, 'rb') as cf:
                certificate = Certificate.load_certificate(cf)

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
            root_ca = Certificate.load_certificate(cf)

        pub_key = SM2PublicKey(SM2Point.from_bytes(root_ca.subject_public_key_info[1].value[0]))

        sig_seq = asn1_decode(root_ca.signature_value[0])[0]
        r = sig_seq.value[0].value.to_bytes(length=32, byteorder='big', signed=False)
        s = sig_seq.value[1].value.to_bytes(length=32, byteorder='big', signed=False)

        print(pub_key.verify(root_ca._tbs_certificate_obj.octets, r + s))

        cert_file = abspath(join(__file__, pardir, 'x509samples', 'sm2.oca.der'))
        with open(cert_file, 'rb') as cf:
            middle_ca = Certificate.load_certificate(cf)

        sig_seq = asn1_decode(middle_ca.signature_value[0])[0]
        r = sig_seq.value[0].value.to_bytes(length=32, byteorder='big', signed=False)
        s = sig_seq.value[1].value.to_bytes(length=32, byteorder='big', signed=False)
        print(pub_key.verify(middle_ca._tbs_certificate_obj.octets, r + s))















