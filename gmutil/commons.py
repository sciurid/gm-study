from typing import Union
from abc import ABC, abstractmethod


class Codec(ABC):
    """用以表示可以多次输入数据（字节串），并按某个规则转换为输出数据（字节串）的抽象基类。

    数据填充、分组加密等算法都可以用此类实现，典型使用方式如下：
    codec = Codec()
    result = bytearray()  # 输出数据
    result.extend(codec.update(input_octets_1))  # 输入数据第一部分
    result.extend(codec.update(input_octets_2))  # 输入数据第二部分
    result.extend(codec.finalize())  # 结束输入
    """

    @abstractmethod
    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        """接受输入数据的函数，当输出数据可用时返回全部可输出数据，否则返回空字节串

        :param 输入字节串
        """
        raise NotImplementedError()

    @abstractmethod
    def finalize(self) -> bytes:
        """完成输入数据的函数，当输出数据可用时返回全部可输出数据，否则返回空字节串
        """
        raise NotImplementedError()


class BlockCipherAlgorithm(ABC):
    """用于表示分组加密算法的抽象基类，在本项目中仅有SM4算法实现"""
    def __init__(self, block_size: int):
        self._block_size = block_size

    @property
    @abstractmethod
    def block_size(self) -> int:
        """分组长度"""
        raise NotImplementedError()

    @abstractmethod
    def encrypt_block(self, in_octets: Union[bytes, bytearray, memoryview]) -> bytes:
        """分组加密函数

        :param in_octets: 待加密的明文数据，长度应当与分组长度相同
        :return: 加密后的密文数据，通常与分组长度相同
        """
        raise NotImplementedError()

    @abstractmethod
    def decrypt_block(self, in_octets: Union[bytes, bytearray, memoryview]) -> bytes:
        """分组解密函数

        :param in_octets: 待解密的密文数据，长度应当与分组长度相同
        :return: 解密后的明文数据，通常与分组长度相同
        """
        raise NotImplementedError()
