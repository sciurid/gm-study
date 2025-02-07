import pem
from asn1util import asn1_print_data, ASN1Sequence
from gmutil import SM2PrivateKey, SM2PublicKey

keys = pem.parse_file('sm2prikey.pem')
print(keys)


print(keys[0].as_text())
print(keys[0].decoded_payload.hex(' '))
print(asn1_print_data(keys[0].decoded_payload))

keypair_data = ASN1Sequence.from_bytes(keys[0].decoded_payload).value[2].value


print(asn1_print_data(keypair_data))

keypair = ASN1Sequence.from_bytes(keypair_data).value

prikey = SM2PrivateKey.from_bytes(keypair[1].value)
pubkey = SM2PublicKey.from_bytes(keypair[2].value[0].value)
print(prikey)
print(prikey.public_key)
print(pubkey)
assert prikey.public_key == pubkey