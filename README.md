# GMUtil

## 介绍

实现SM2/SM3/SM4国密算法的纯Python库，对照以下国家标准编写：

- 《信息安全技术 SM2椭圆曲线公钥密码算法 第1部分：总则》（GB/T 32981.1-2016）
- 《信息安全技术 SM2椭圆曲线公钥密码算法 第2部分：数字签名算法》（GB/T 32981.2-2016）
- 《信息安全技术 SM2椭圆曲线公钥密码算法 第3部分：密钥交换协议》（GB/T 32981.3-2016）
- 《信息安全技术 SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法》（GB/T 32981.4-2016）
- 《信息安全技术 SM2椭圆曲线公钥密码算法 第5部分：参数定义》（GB/T 32981.5-2017）
- 《信息安全技术 SM3密码杂凑算法》（GB/T 32905-2016）
- 《信息安全技术 SM4分组密码算法》（GB/T 32907-2016）

Python版本的SM2/SM3/SM4算法在<a href = "https://github.com/py-gmssl/py-gmssl">py-gmssl</a>项目中实现；
SM3/SM4算法在<a href = "https://github.com/pyca/cryptography">pyca/cryptograph</a>项目中已经实现。
本项目的编写过程中学习了py-gmssl的代码实现，在此特别致谢。

本算法库的主要目的是学习和研究国密算法的实现，并不在于重复造轮子。
因此，本算法库的代码中尽可能地增加了中文注释和对应的标准文本描述，以尽可能帮助理解。
如果有学习者有疑问的，可以在Issue中提出。

## 使用方法

### 下载和安装

```
git clone https://gitee.com/LanceChen/gmutil.git
pip install -e gmutil
```

### SM3哈希/杂凑

```
# GB/T 32905-2016 附录A
from gmutil import sm3_hash

# A.1 示例1
sample_1 = bytes.fromhex('616263')
result_1 = bytes.fromhex('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
assert sm3_hash(sample_1) == result_1

# A.2 示例2
sample_2 = bytes.fromhex('61626364' * 16)
result_2 = bytes.fromhex('debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')
assert sm3_hash(sample_2) == result_2
```

### SM4加密

```
# GB/T 32097-2016 附录A
# A.1 示例1
message = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
secret_key = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
cipher_text = sm4_encrypt_block(secret_key, message)
self.assertEqual(cipher_text, bytes.fromhex('681EDF34 D206965E 86B3E94F 536E4246'))
restored = sm4_decrypt_block(secret_key, cipher_text)
self.assertEqual(message, restored)

# A.2 示例2
sm4 = SM4(secret_key)
cipher_text = message
for _ in range(1000000):
    cipher_text = sm4.encrypt_block(cipher_text)
    if _ % 10000 == 0:
        print(_)
self.assertEqual(cipher_text, bytes.fromhex('595298C7 C6FD271F 0402F804 C33D3F66'))
```

### SM4分组密码的工作模式

```
plain_text = '飞流直下三千尺，疑似银河落九天。'.encode('utf-8')
secret_key = secrets.randbits(SM4.BLOCK_SIZE).to_bytes(16, byteorder='big', signed=False)
iv = secrets.randbits(SM4.BLOCK_SIZE).to_bytes(16, byteorder='big', signed=False)
print(secret_key.hex())
print(iv.hex())

encryptor = SM4Encryptor(secret_key, 'CBC', 'PKCS7', iv=iv)
cipher_text = encryptor.update(plain_text) + encryptor.finalize()
print(cipher_text.hex())

decryptor = SM4Decryptor(secret_key, 'CBC', 'PKCS7', iv=iv)
restored = decryptor.update(plain_text) + decryptor.finalize()
print(restored.hex())

```

### SM2签名和验签（SM3哈希/杂凑）

```
message = 'A fox jumps over the lazy dog.'  # 明文
print("Message:", message.encode().hex())

prikey = SM2PrivateKey()  # 生成私钥
print("Private Key:", prikey.to_bytes().hex())
signature = prikey.sign(message.encode())  # 私钥签名
print("Signature:", signature.hex().upper())

pubkey = prikey.get_public_key()  # 从私钥中取得公钥
print("Public Key:", pubkey)
assert pubkey.verify(message.encode(), signature)    # 公钥验签
```

### SM2加密和解密

```
message = 'A fox jumps over the lazy dog.'  # 明文
print("Message:", message.encode('ascii').hex())

prikey = SM2PrivateKey()  # 生成私钥
print("Private Key:", prikey.to_bytes().hex())
pubkey = prikey.get_public_key()  # 从私钥中取得公钥
print("Public Key:", pubkey)

cipher_text = pubkey.encrypt(message.encode())  # 公钥加密
print("Cipher Text:", cipher_text.hex().upper())  # 密文

recovered = prikey.decrypt(cipher_text)  # 私钥解密
print("Recovered:", recovered.hex().upper())
print("Message:", recovered.decode('ascii'))  # 明文

self.assertEqual(message, recovered.decode('ascii'))
```

### SM2密钥交换

#### 简单形式
```
user_a = SM2KeyExchange(uid='user-a'.encode())  # 用户A
user_b = SM2KeyExchange(uid='user-b'.encode())  # 用户B

# 向对方传输各自的公钥、随机点、用户身份ID
key_a = user_a.calculate_key(True, *user_b.send())  # 用户A计算共享密钥
key_b = user_b.calculate_key(False, *user_a.send())  # 用户B计算共享密钥

print("Key A:", key_a.hex())
print("Key B:", key_b.hex())
assert key_a == key_b
```

#### 可选形式

增加了密钥协商后的确认环节。

```
user_a = SM2KeyExchangePartyA(uid='user-a'.encode())
user_b = SM2KeyExchangePartyB(uid='user-b'.encode())

user_b.receive_1(*user_a.send_1())   # A向B发送协商密钥长度、公钥A、随机点A、用户A身份ID
user_a.receive_2(*user_b.send_2())   # B向A发送公钥B、随机点B、用户B身份ID、验证值S_B
user_b.receive_3(*user_a.send_3())   # A向B发送验证值S_A

print("Key A:", user_a.exchanged_key.hex())
print("Key B:", user_b.exchanged_key.hex())

self.assertEqual(user_a.exchanged_key, user_b.exchanged_key)
```

### 消息验证码 

#### HMAC与SM3

```
# GB/T 15852.2-2024 C.2
buffer = StringIO()
for i in range(1000000):
    buffer.write('a')

messages = (
    '', 'a', 'abc', 'message digest',
    'abcdefghijklmnopqrstuvwxyz', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    '1234567890' * 8,
    buffer.getvalue()
)


key_1 = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
key_2 = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')

# 密钥 1 的 MAC 值
mac_key1 = [
    "C8E4E95012EB3D449B5DD0691947986E469E08A3506BB55CCB94A96EBFADA654",
    "5FD9F7568A24C438F14B7A22E799B0689FE053ABB76D316202E3C9D10E9EEBE2",
    "0933617A88D312F6F9FB4B5F200E31A64D655E92F7FA2A43F55DFEEB8AB6788D",
    "9C9A22E8B5797B82CFF9BABA56893CC1D75811C334D198F3AF43401740B824F7",
    "A51CE58C52AE29EDD66A53E6AAF0745BF4FEDBDE899973B2D817290E646DF87E",
    "DC813339153491AD81477754EB3DF00DBB3CC3E6A69F9CACCE737DB7E61342FF",
    "BCA6FA751AECAC5BA3AC49963F6A58F7C2293C6E6923802BC52117A741A49FEE",
    "25E034DF9A3AC81599C233440CA6F68F38CA5166438BFA620210EC2F59880C0D",
    "34DB1B0452359EA54DA16932E42A662BE88C19C5AD4FE9073867C05A92752024"
]

# 密钥 2 的 MAC 值
mac_key2 = [
    "F14B797B559216B73D3816ADFB790250AF3F21198A1AE867123762BB63A00945",
    "5BD1836B97C74F88A77BC309E77A269481F53BE9D5C4CE1E40B1C50FE574762E",
    "28D8A61BE67D8BF7652C4EDA7092B612F88BE62184F55005C57DDF076E764199",
    "E0ACCC4DA77E77D135F17F5CA1EE3E600DAB444FC23ADD6F7E6A54E1B34B26BC",
    "429D9030B1D992AD8198E01C13141C2859A913D69DE00CCE9E4A60F00BF276CB",
    "AAB294F80562AB234E6226BF7FC3B03F839C7759E60F69735B7E99E50EB94A24",
    "08F457B37E5E062AFAFB24DE8D48B92246F1788BAAD4D7B3D11E5F627E33A0D3",
    "9F85C779D718A33BDEC2D6E0C1F280FE6A8C12FF2521530A44D168DD4080BC14",
    "ED3057AB0DB1E826240FCF8E8760C3DB9338E9AABDAD8B11BB0C040D73E74441"
]


for ind, message in enumerate(messages):
    # print(message)
    hk1 = hmac_sm3(key_1, message.encode())
    hk2 = hmac_sm3(key_2, message.encode())
    # print(xor_on_bytes(hk1, bytes.fromhex(mac_key1[ind])).hex())
    self.assertEqual(hk1.hex(), mac_key1[ind].lower())
    self.assertEqual(hk2.hex(), mac_key2[ind].lower())

```

#### GMAC与SM4

```
# GB/T 15852.3-2019 附录A
mine = gmac_sm4(key=b'\x00' * 16, message=b'', n=b'\x00' * 12)
ref = bytes.fromhex('23 2f 0c fe 30 8b 49 ea 6f c8 82 29 b5 dc 85 8d')
self.assertEqual(mine, ref)

mine = gmac_sm4(
    key=bytes.fromhex('fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08'),
    message=bytes.fromhex('fe ed fa ce de ad be ef fe ed fa ce de ad be ef'),
    n=bytes.fromhex('ca fe ba be fa ce db ad de ca f8 88')
)

ref = bytes.fromhex('9d 63 25 70 f9 30 64 26 4a 20 91 8e 30 81 b4 cd')
self.assertEqual(ref, mine)

mine = gmac_sm4(
    key=bytes.fromhex('fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08'),
    message=bytes.fromhex('fe ed fa ce de ad be ef fe ed fa ce de ad be ef'
                          'ab ad da d2 42 83 1e c2 21 77 74 24 4b 72 21 b7'),
    n=bytes.fromhex('ca fe ba be fa ce db ad de ca f8 88')
)

ref = bytes.fromhex('1e ea eb 66 9e 96 bd 05 9b d9 92 91 23 03 0e 78')
self.assertEqual(ref, mine)
```

#### SM4-GCM

```
key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
p = bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
                  "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
iv = bytes.fromhex("00001234567800000000ABCD")
aad = bytes.fromhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")

c, t = gcm_encrypt(sm4_encrypt_block, key, p, iv, aad)
self.assertEqual(c, bytes.fromhex("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735
                                  "D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D"))
self.assertEqual(t, bytes.fromhex("83DE3541E4C2B58177E065A9BF7B62EC"))
print(c.hex(), t.hex())

r = gcm_decrypt(sm4_encrypt_block, key, iv, aad, c, t)
self.assertEqual(r, p)

```



## 待开发

- SM2私钥和公钥的保存格式（数字证书格式）
- SM4加密的HCTR工作方式
