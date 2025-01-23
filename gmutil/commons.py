from typing import Union


class Codec:
    """用以表示可以多次输入数据（字节串），并按某个规则转换为输出数据（字节串）的抽象基类。

    数据填充、分组加密等算法都可以用此类实现，典型使用方式如下：
    codec = Codec()
    result = bytearray()  # 输出数据
    result.extend(codec.update(input_octets_1))  # 输入数据第一部分
    result.extend(codec.update(input_octets_2))  # 输入数据第二部分
    result.extend(codec.finalize())  # 结束输入
    """
    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        """接受输入数据的函数，当输出数据可用时返回输出数据
        """
        raise NotImplementedError()

    def finalize(self) -> bytes:
        """完成输入数据的函数，当输出数据可用时返回输出数据
        """
        raise NotImplementedError()