from gmutil.calculation import *

# 基域特征 q
Q = int.from_bytes(bytes.fromhex("B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D"),
                   byteorder='big', signed=False)

# 方程参数 b
B = "05"

# 群 G1, G2 的阶 N
N = int.from_bytes(bytes.fromhex("B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25"),
                   byteorder='big', signed=False)

# 群 G1 的生成元 P1 的坐标 x_P1
X_P1 = int.from_bytes(bytes.fromhex("93DE051D 62BF718F F5ED0704 487D01D6 E1E40869 09DC3280 E8C4E481 7C66DDDD"),
                   byteorder='big', signed=False)

# 群 G1 的生成元 P1 的坐标 y_P1
Y_P1 = int.from_bytes(bytes.fromhex("21FE8DDA 4F21E607 63106512 5C395BBC 1C1C00CB FA602435 0C464CD7 0A3EA616"),
                   byteorder='big', signed=False)

# 群 G2 的生成元 P2 的坐标 x_P2
X_P2 = int.from_bytes(bytes.fromhex(("85AEF3D0 78640C98 597B6027 B441A01F F1DD2C19 0F5E93C4 54806C11 D8806141"
        "37227552 92130B08 D2AAB97F D34EC120 EE265948 D19C17AB F9B7213B AF82D65B")),
                   byteorder='big', signed=False)

# 群 G2 的生成元 P2 的坐标 y_P2
Y_P2 = int.from_bytes(bytes.fromhex(("17509B09 2E845C12 66BA0D26 2CBEE6ED 0736A96F A347C8BD 856DC76B 84EBEB96"
        "A7CF28D5 19BE3DA6 5F317015 3D278FF2 47EFBA98 A71A0811 6215BBA5 C999A7C7")),
                   byteorder='big', signed=False)

# 签名主私钥 k_s
K_S = int.from_bytes(bytes.fromhex("0130E7 8459D785 45CB54C5 87E02CF4 80CE0B66 340F319F 348A1D5B 1F2DC5F4"),
                   byteorder='big', signed=False)

# 签名主公钥 P_pub,s 的坐标 x_P_pub,s
X_P_PUB_S = int.from_bytes(bytes.fromhex(("9F64080B 3084F733 E48AFF4B 41B56501 1CE0711C 5E392CFB 0AB1B679 1B94C408"
             "29DBA116 152D1F78 6CE843ED 24A3B573 414D2177 386A92DD 8F14D656 96EA5E32")),
                   byteorder='big', signed=False)

# 签名主公钥 P_pub,s 的坐标 y_P_pub,s
Y_P_PUB_S = int.from_bytes(bytes.fromhex(("69850938 ABEA0112 B57329F4 47E3A0CB AD3E2FDB 1A77F335 E89E1408 D0EF1C25"
             "41E00A53 DDA532DA 1A7CE027 B74F4674 1006E85F 5CDFF073 0E75C05F B4E3216D")),
                   byteorder='big', signed=False)

# 实体 A 的标识 ID_A 的 16 进制表示
ID_A_HEX = "416C6963 65"

ECC_A = 0

ECC_B = 5


BETA = int.from_bytes(bytes.fromhex('6C648DE5DC0A3F2CF55ACC93EE0BAF159F9D411806DC5177F5B21FD3DA24D717'),
                      byteorder='big', signed=False)

POW_Q_2 = Q * Q

print(mul_mod_prime(POW_Q_2, BETA, BETA))


def on_curve_Q(x, y):
    pow_y_2 = mul_mod_prime(Q, y, y)
    pow_x_3 = pow_mod_prime(Q, x, 3)
    return pow_y_2 == add_mod_prime(Q, pow_x_3, ECC_B)



assert Q % 4 == 1

a = square_root_mod_prime(Q, Q - 2)
b = square_root_mod_prime(Q, 2)
print(a, b)



def on_curve_Q2(x, y):
    pow_y_2 = mul_mod_prime(POW_Q_2, y, y)
    pow_x_3 = pow_mod_prime(POW_Q_2, x, 3)
    beta = div_mod_prime(POW_Q_2, minus_mod_prime(POW_Q_2, pow_y_2, pow_x_3), ECC_B)
    print(mul_mod_prime(POW_Q_2, beta, beta))
    print(div_mod_prime(POW_Q_2, minus_mod_prime(POW_Q_2, pow_y_2, pow_x_3), ECC_B))





assert on_curve_Q(X_P1, Y_P1)
on_curve_Q2(X_P2, Y_P2)


def miller_g(x_p, y_p, x_q, y_q):
    pass



def miller(x_p, y_p, x_q, y_q, c: int):
    assert (x_p is None) == (y_p is None)
    assert (x_q is None) == (y_q is None)

    j = c.bit_length()
    print(f'c = {c:0b}')
    f = 1
    for i in range(j - 1, -1, -1):
        mul_mod_prime(q, f, f)



