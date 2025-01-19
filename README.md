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

### SM3哈希

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

### SM4 加密

```
# GB/T 32097-2016 附录A
# A.1 示例1
message = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
secrets = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
cipher_text = sm4_encrypt(message, secrets)
assert cipher_text == bytes.fromhex('681EDF34 D206965E 86B3E94F 536E4246')

restored = sm4_decrypt(cipher_text, secrets)
assert message == restored

# A.2 示例2
sm4 = SM4(secrets)
cipher_text = message
for _ in range(1000000):
    cipher_text = sm4.encrypt_block(cipher_text)
    print(_)
assert cipher_text == bytes.fromhex('595298C7 C6FD271F 0402F804 C33D3F66')
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

## 待开发

- SM2私钥和公钥的保存格式
- SM4加密的补齐（padding）和模式（mode）
