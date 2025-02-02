from typing import Callable, Union, Optional, Tuple

from . import uint_incr
from .calculation import xor_on_bytes, mul_gf_2_128
from .commons import Codec, BlockCipherAlgorithm
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class Mode(ABC):
    def __init__(self, algorithm: Optional[BlockCipherAlgorithm] = None):
        self._algorithm = None
        self._block_size = None
        self._block_byte_len = None
        if algorithm is not None:
            self.set_algorithm(algorithm)

    @property
    def block_byte_len(self):
        return self._block_byte_len

    def set_algorithm(self, algorithm: BlockCipherAlgorithm):
        """设置要使用的分组密码算法

        :param algorithm: BlockCipherAlgorithm 分组密码算法
        """
        self._algorithm = algorithm
        self._block_size = self._algorithm.block_size
        if self._block_size % 8 != 0:
            raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8')
        self._block_byte_len = self._block_size // 8

    @abstractmethod
    def encryptor(self) -> Codec:
        raise NotImplementedError()

    @abstractmethod
    def decryptor(self) -> Codec:
        raise NotImplementedError()


class BlockwiseInnerCodec(Codec, ABC):
    """EBC/CBC/CTR等分组工作模式内部使用的加解密工具类"""
    def __init__(self, mode: Mode):
        self._mode = mode
        self._buffer = bytearray()

    @abstractmethod
    def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
        """处理单个分组的函数

        EBC/CBC加密解密实现不同、CTR加密解密实现相同
        :param in_block: 输入分组
        """
        raise NotImplementedError()

    def _process_buffer(self) -> bytes:
        """处理缓冲区中输入数据的函数"""
        out_octets = bytearray()
        buffer_len = len(self._buffer)
        block_byte_len = self._mode.block_byte_len
        if buffer_len >= self._mode.block_byte_len:
            in_octets = memoryview(self._buffer)
            m, n = 0, block_byte_len
            while n <= buffer_len:  # 处理每一个完整的分组
                out_octets.extend(self._process_block(in_octets[m:n]))
                m = n
                n = m + block_byte_len
            self._buffer = self._buffer[m:]
        return out_octets

    def update(self, in_octets: bytes) -> bytes:
        self._buffer.extend(in_octets)
        return bytes(self._process_buffer())

    def finalize(self) -> bytes:
        if len(self._buffer) != 0:
            raise ValueError('数据长度不是分组长度的整数倍，需要填充/'
                             'Length of data is not a multiple of block size, so padding is required')
        return b''


class ECB(Mode):
    """电码本（ECB）模式，规定于GB/T 17964-2021 5"""
    def __init__(self, algorithm: Optional[BlockCipherAlgorithm] = None):
        """初始化函数

        :param algorithm: 分组密码算法
        """
        super().__init__(algorithm)

    class Encryptor(BlockwiseInnerCodec):
        def __init__(self, mode: Mode):
            super().__init__(mode)

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
            return self._mode._algorithm.encrypt_block(in_block)

    class Decryptor(BlockwiseInnerCodec):
        def __init__(self, mode: Mode):
            super().__init__(mode)

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
            return self._mode._algorithm.decrypt_block(in_block)

    def encryptor(self) -> Encryptor:
        return ECB.Encryptor(self)

    def decryptor(self) -> Decryptor:
        return ECB.Decryptor(self)


class CBC(Mode):
    """密文分组链接（CBC）模式，规定于GB/T 17964-2021 7"""
    def __init__(self, iv: Union[bytes, bytearray, memoryview], algorithm: Optional[BlockCipherAlgorithm] = None):
        """初始化函数

        :param iv: 初始向量IV，由加解密双方约定或者由加密方提供给解密方
        :param algorithm: 分组密码算法
        """
        self._iv = iv
        super().__init__(algorithm)
        self._last_cipher_block = iv

    def set_algorithm(self, algorithm: BlockCipherAlgorithm):
        if len(self._iv) * 8 != algorithm.block_size:
            raise ValueError('初始向量IV必须为分组长度/Initial vector should be of block size.')
        super().set_algorithm(algorithm)

    class Encryptor(BlockwiseInnerCodec):

        def __init__(self, mode: 'CBC'):
            super().__init__(mode)
            self._last_cipher_block = mode._iv

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
            to_encrypt = xor_on_bytes(self._last_cipher_block, in_block)  # 输入分组与上一组密文异或
            self._last_cipher_block = self._mode._algorithm.encrypt_block(to_encrypt)  # 使用加密函数形成密文，并保存用于下一组处理
            return self._last_cipher_block

    class Decryptor(BlockwiseInnerCodec):
        def __init__(self, mode: 'CBC'):
            super().__init__(mode)
            self._last_cipher_block = mode._iv

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
            decrypted = xor_on_bytes(self._mode._algorithm.decrypt_block(in_block), self._last_cipher_block)
            # 输入分组解密后与上一组密文异或，形成明文
            self._last_cipher_block = in_block  # 保留本组输入（密文）作为用于下一组处理
            return decrypted

    def encryptor(self) -> Encryptor:
        return CBC.Encryptor(self)

    def decryptor(self) -> Decryptor:
        return CBC.Decryptor(self)


class CTR(Mode):
    """计数器（CTR）模式，规定于GB/T 17964-2021 9"""
    def __init__(self, iv: Union[bytes, bytearray, memoryview], algorithm: Optional[BlockCipherAlgorithm] = None):
        self._iv = iv
        super().__init__(algorithm)

    def set_algorithm(self, algorithm: BlockCipherAlgorithm):
        if len(self._iv) * 8 != algorithm.block_size:
            raise ValueError('初始向量IV必须为分组长度/Initial vector should be of block size.')
        super().set_algorithm(algorithm)

    class InnerCodec(BlockwiseInnerCodec):
        """CTR模式的加密解密是相同算法
        """
        def __init__(self, mode: 'CTR'):
            super().__init__(mode)
            self._last_counter = bytearray(mode._iv)
            self._block_byte_len = mode._block_byte_len
            self._algorithm = mode._algorithm
            self._overflow = 1 << mode._algorithm.block_size

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
            mask = self._algorithm.encrypt_block(self._last_counter)  # 计数器加密为分组掩码
            if len(in_block) == self._block_byte_len:
                out_block = xor_on_bytes(in_block, mask)  # 分组掩码与明文/密文异或得到密文/明文
            else:
                out_block = xor_on_bytes(in_block, memoryview(mask)[0:len(in_block)])

            # 计数器加一并按分组长度循环
            # next_counter = int.from_bytes(self._last_counter, byteorder='big', signed=False) + 1
            # if next_counter == self._overflow:
            #     next_counter = 0
            # self._last_counter = next_counter.to_bytes(length=self._block_byte_len, byteorder='big', signed=False)
            uint_incr(self._last_counter)

            return out_block

        def finalize(self) -> bytes:
            assert len(self._buffer) <= self._block_byte_len
            return self._process_block(self._buffer)  # 尾部数据不足一个分组时无需填充

    def encryptor(self) -> InnerCodec:
        return CTR.InnerCodec(self)

    def decryptor(self) -> InnerCodec:
        return CTR.InnerCodec(self)


class CFB(Mode):
    """密文反馈（CFB）模式，规定于GB/T 17964-2021 7

    CFB模式的分组长度可以短于底层分组加密算法的分组长度，如果取8bit的话则转变为流加密（CFB8）。
    国标规定的长度中还有个反馈变量的长度k，实际中通常取模式的分组长度（k=j）。
    国标中设初始向量IV长度(r) >= 分组加密算法的分组长度(n) >= 反馈密文长度(k) >= 模式分组长度(j)，
    实际应用中通常是r = n > k = j，尚不明确为何采取此种规范。
    """
    def __init__(self, iv: Union[bytes, bytearray, memoryview], algorithm: Optional[BlockCipherAlgorithm] = None,
                 stream_unit_byte_len: Optional[int] = None, feedback_byte_len: Optional[int] = None):
        """初始化函数

        :param iv: 初始向量IV，长度不少于底层分组密码算法的分组长度
        :param algorithm: 底层的分组密码算法
        :param stream_unit_byte_len: CFB模式的分组长度（国标中的j//8），不超过底层的分组密码算法的长度
        :param feedback_byte_len: 反馈变量长度（国标中的k//8），不小于模式的分组长度，不超过底层分组密码算法的分组长度，通常取模式的分组长度
        """
        self._iv = iv
        self._iv_byte_len = len(self._iv)
        super().__init__(algorithm)
        self._stream_unit_byte_len = stream_unit_byte_len if stream_unit_byte_len else self._block_byte_len
        self._feedback_byte_len = feedback_byte_len if feedback_byte_len else self._stream_unit_byte_len

    def set_algorithm(self, algorithm: BlockCipherAlgorithm):
        if len(self._iv) * 8 < algorithm.block_size:
            raise ValueError('初始向量IV必须不小于分组长度/Initial vector should be of block size.')
        super().set_algorithm(algorithm)

    class InnerCodec(Codec, ABC):
        def __init__(self, mode: 'CFB'):
            self._mode = mode
            self._algorithm = mode._algorithm
            self._block_byte_len = mode._block_byte_len
            self._stream_unit_byte_len = mode._stream_unit_byte_len

            self._buffer = bytearray()
            self._fb = bytearray(self._mode._iv)
            self._iv_byte_len = len(self._mode._iv)
            self._ex_padding = b'\xff' * (self._mode._feedback_byte_len - self._mode._stream_unit_byte_len)

        @abstractmethod
        def _process_block(self, in_block: Union[bytes, bytearray, memoryview], val_y: memoryview
                           ) -> Tuple[bytes, bytes]:
            """对于每个分组的处理流程，加密和解密不同

            :param in_block: 输入数据，长度为模式分组长度
            :return: 二元组(用于反馈的密文, 用于输出的密文（加密时）或明文（解密时）)
            """
            raise NotImplementedError()

        def _process_buffer(self):
            out_octets = bytearray()
            in_octets = memoryview(self._buffer)
            buffer_len = len(self._buffer)
            m = 0
            n = self._stream_unit_byte_len
            while n <= buffer_len:
                val_x = memoryview(self._fb)[0:self._block_byte_len]  # FB的左侧取分组密码算法的分组长度，用于加密形成掩码
                val_y = memoryview(self._mode._algorithm.encrypt_block(val_x))[0:self._stream_unit_byte_len]  # 掩码
                val_x.release()

                val_c, val_out = self._process_block(in_octets[m:n], val_y)  # 用于反馈的密文和用于输出的密文/明文（加密时/解密时）
                out_octets.extend(val_out)

                self._fb.extend(self._ex_padding)  # 如果反馈长度比模式分组长度长，则在密文分组左侧补足二进制1，通常k=j时为空
                self._fb.extend(val_c)  # 反馈密文
                self._fb = self._fb[-self._iv_byte_len:]  # 取FB的最右侧的初始向量分组长度

                m = n
                n = m + self._stream_unit_byte_len  # 输入的下一个模式分组

            in_octets.release()
            self._buffer = self._buffer[m:]
            return out_octets

        def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
            self._buffer.extend(octets)
            return bytes(self._process_buffer())

        def finalize(self) -> bytes:
            buffer_len = len(self._buffer)
            if buffer_len % self._stream_unit_byte_len != 0:
                self._buffer.extend(b'\x00' * (self._stream_unit_byte_len - buffer_len))
            out_octets = self._process_buffer()
            return bytes(out_octets[0:buffer_len])

    class Encryptor(InnerCodec):
        def __init__(self, mode: 'CFB'):
            super().__init__(mode)

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview], val_y: memoryview
                           ) -> Tuple[bytes, bytes]:
            # 加密时返回密文用于反馈，同时返回密文用于输出
            val_c = xor_on_bytes(val_y, in_block)
            return val_c, val_c

    class Decryptor(InnerCodec):
        def __init__(self, mode: 'CFB'):
            super().__init__(mode)

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview], val_y: memoryview
                           ) -> Tuple[bytes, bytes]:
            # 解密时返回密文用于反馈，同时返回明文用于输出
            return in_block, xor_on_bytes(val_y, in_block)

    def encryptor(self) -> Encryptor:
        return CFB.Encryptor(self)

    def decryptor(self) -> Decryptor:
        return CFB.Decryptor(self)


class OFB(Mode):
    """输出反馈（OFB）模式，规定于GB/T 17964-2021 8"""
    def __init__(self, iv: Union[bytes, bytearray, memoryview], algorithm: Optional[BlockCipherAlgorithm] = None,
                 stream_unit_byte_len: Optional[int] = None):
        super().__init__(algorithm)
        self._iv = iv
        self.set_algorithm(algorithm)
        self._stream_unit_byte_len = stream_unit_byte_len if stream_unit_byte_len else self._block_byte_len
        self._iv = iv

    class InnerCodec(Codec):
        def __init__(self, mode: 'OFB'):
            self._mode = mode
            self._algorithm = mode._algorithm  # 分组加密算法
            self._stream_unit_byte_len = mode._stream_unit_byte_len  # 模式分组长度
            self._fb = mode._iv  # 反馈变量
            self._buffer = bytearray()  # 输入缓冲区

        def _process_buffer(self):
            out_octets = bytearray()
            in_octets = memoryview(self._buffer)
            buffer_len = len(self._buffer)
            m = 0
            n = self._stream_unit_byte_len
            while n <= buffer_len:
                val_y = self._algorithm.encrypt_block(self._fb)  # 加密反馈变量用作掩码
                # 掩码左侧部分（长度为模式分组长度）与输入明文/密文异或形成密文/明文并输出
                out_octets.extend(xor_on_bytes(memoryview(val_y)[0:self._stream_unit_byte_len], in_octets[m:n]))
                self._fb = val_y  # 掩码作为下一组的反馈变量

                m = n
                n = m + self._stream_unit_byte_len

            in_octets.release()
            self._buffer = self._buffer[m:]
            return out_octets

        def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
            self._buffer.extend(octets)
            return bytes(self._process_buffer())

        def finalize(self) -> bytes:
            buffer_len = len(self._buffer)
            if buffer_len % self._stream_unit_byte_len != 0:
                self._buffer.extend(b'\x00' * (self._stream_unit_byte_len - buffer_len))
            out_octets = self._process_buffer()
            return bytes(out_octets[0:buffer_len])

    def encryptor(self) -> InnerCodec:
        return OFB.InnerCodec(self)

    def decryptor(self) -> InnerCodec:
        return OFB.InnerCodec(self)


class XTS(Mode):
    def __init__(self, algorithm: BlockCipherAlgorithm = None):
        super().__init__(algorithm)
        self._step_mask = None

        self._buffer = bytearray()

    def set_algorithm(self, algorithm: BlockCipherAlgorithm):
        super().set_algorithm(algorithm)
        if self._block_size != 128:
            raise ValueError("XTS模式目前只支持128-bit的分组长度/Only 128-bit block algorithm is supported by XTS mode.")

    def set_tweak(self, tweak: Union[bytes, bytearray, memoryview], tweak_algorithm: BlockCipherAlgorithm):
        self._step_mask = tweak_algorithm.encrypt_block(tweak)  # 初始掩码由调柄（tweak）值进行分组加密计算获得

    POLYNOMIAL_ALPHA: int = 1 << 126

    @staticmethod
    def _next_step_mask(polynomial_mask: bytes):
        """计算下个分组的输入输出掩码，即使用GF(2^128）上的多项式乘法乘以不定元{\\alpha}"""
        return mul_gf_2_128(int.from_bytes(polynomial_mask, byteorder='big', signed=False),
                            XTS.POLYNOMIAL_ALPHA).to_bytes(length=16, byteorder='big', signed=False)

    class InnerCodec(Codec, ABC):
        def __init__(self, mode: 'XTS'):
            self._mode = mode
            self._step_mask = mode._step_mask
            self._algorithm = mode._algorithm
            self._block_byte_len = mode._block_byte_len

            self._buffer = bytearray()

        @abstractmethod
        def _process_block(self, in_block: Union[bytes, bytearray, memoryview]):
            raise NotImplementedError()

        def _process_buffer(self) -> bytearray:
            out_octets = bytearray()
            in_octets = memoryview(self._buffer)
            buffer_len = len(self._buffer)
            m = 0
            n = self._block_byte_len
            while n <= buffer_len - self._block_byte_len:  # 保留至少一个完整分组以及可能的后续不足一个分组
                out_octets.extend(self._process_block(in_octets[m:n]))  # 计算当前分组的密文/明文
                self._step_mask = XTS._next_step_mask(self._step_mask)  # 计算下一组的掩码
                m = n
                n = m + self._block_byte_len
            self._buffer = self._buffer[m:]
            return out_octets

        def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
            self._buffer.extend(octets)
            return bytes(self._process_buffer())

        @abstractmethod
        def _do_stealing(self, in_octets: memoryview, d: int, n_d: int, out_octets: bytearray) -> bytes:
            """实现最后两组密文/明文（最后一组不足分组长度）的挪用"""
            raise NotImplementedError()

        def finalize(self) -> bytes:
            buffer_len = len(self._buffer)
            assert buffer_len < 2 * self._block_byte_len
            if buffer_len < self._block_byte_len:
                raise ValueError(
                    '数据长度不足一个分组，需要补齐/Data is shorter than one block, so padding is required.')

            in_octets = memoryview(self._buffer)
            out_octets = bytearray()

            if buffer_len == self._block_byte_len:  # 只有一个完整分组时，无需密文挪用
                out_octets.extend(self._process_block(in_octets))
            else:  # 剩余一个完整分组和后续不足一个分组时，进行密文挪用
                d = buffer_len - self._block_byte_len
                n_d = self._block_byte_len - d
                self._do_stealing(in_octets, d, n_d, out_octets)  # 将最后两个分组进行密文挪用（最后一个分组不完整）
            return bytes(out_octets)

    class Encryptor(InnerCodec):
        def __init__(self, mode: 'XTS'):
            super().__init__(mode)

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
            enc_in = xor_on_bytes(self._step_mask, in_block)
            enc_out = self._algorithm.encrypt_block(enc_in)
            out_block = xor_on_bytes(self._step_mask, enc_out)
            return bytes(out_block)

        def _do_stealing(self, in_octets: memoryview, d: int, n_d: int, out_octets: bytearray) -> bytes:
            c_ql = self._process_block(in_octets[0:self._block_byte_len])  # 计算倒数第二组密文
            self._step_mask = XTS._next_step_mask(self._step_mask)  # 计算下一组掩码
            ex = bytearray(in_octets[self._block_byte_len:])
            ex.extend(c_ql[-n_d:])
            c_q = self._process_block(ex)

            out_octets.extend(c_q)
            out_octets.extend(c_ql[0:d])

    class Decryptor(InnerCodec):
        def __init__(self, mode: 'XTS'):
            super().__init__(mode)

        def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
            enc_in = xor_on_bytes(self._step_mask, in_block)
            enc_out = self._algorithm.decrypt_block(enc_in)
            out_block = xor_on_bytes(self._step_mask, enc_out)
            return bytes(out_block)

        def _do_stealing(self, in_octets: memoryview, d: int, n_d: int, out_octets: bytearray) -> bytes:
            mask_ql = self._step_mask
            self._step_mask = XTS._next_step_mask(self._step_mask)
            p_q = self._process_block(in_octets[0:self._block_byte_len])
            ex = bytearray(in_octets[self._block_byte_len:])
            ex.extend(p_q[-n_d:])
            self._step_mask = mask_ql
            p_ql = self._process_block(ex)
            out_octets.extend(p_ql)
            out_octets.extend(p_q[0:d])

    def encryptor(self):
        return XTS.Encryptor(self)

    def decryptor(self):
        return XTS.Decryptor(self)


def get_mode(mode_name: str, algorithm: BlockCipherAlgorithm, **kwargs):
    mode_name = mode_name.upper()
    if mode_name == 'ECB':
        return ECB(algorithm=algorithm)
    elif mode_name == 'CBC':
        return CBC(iv=kwargs['iv'], algorithm=algorithm)
    elif mode_name == 'CFB':
        return CFB(iv=kwargs['iv'], algorithm=algorithm, stream_unit_byte_len=kwargs['stream_unit_byte_len'])
    elif mode_name == 'CFB8':
        return CFB(iv=kwargs['iv'], algorithm=algorithm, stream_unit_byte_len=1)
    elif mode_name == 'CFB128':
        return CFB(iv=kwargs['iv'], algorithm=algorithm, stream_unit_byte_len=16)
    elif mode_name == 'OFB':
        return OFB(iv=kwargs['iv'], algorithm=algorithm, stream_unit_byte_len=kwargs['stream_unit_byte_len'])
    elif mode_name == 'OFB8':
        return OFB(iv=kwargs['iv'], algorithm=algorithm, stream_unit_byte_len=1)
    elif mode_name == 'OFB128':
        return OFB(iv=kwargs['iv'], algorithm=algorithm, stream_unit_byte_len=16)
    elif mode_name == 'CTR':
        return CTR(iv=kwargs['iv'], algorithm=algorithm)
    elif mode_name == 'XTS':
        xts = XTS(algorithm=algorithm)
        xts.set_tweak(kwargs['tweak'], kwargs['tweak_algorithm'])
        return xts
    else:
        raise ValueError()

