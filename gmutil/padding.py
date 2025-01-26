from typing import Union, Optional
from .commons import Codec


class PaddingException(Exception):

    def __init__(self, *args):
        super().__init__(*args)


class PKCS7Padding(Codec):
    """PKCS#7填充方法类。

    与GB/T 17964-2021 C.2相同。
    """

    def __init__(self, block_size: int, mode_padding: bool):
        super().__init__()
        if not (0 < block_size < 2048):
            raise PaddingException('分组大小必须大于0小于2048/Block size should be between 0 and 2048 exclusive')
        if block_size % 8 != 0:
            raise PaddingException('分组大小必须为8的倍数/Block size should be a multiple of 8')
        self._block_size = block_size
        self._block_byte_len = block_size // 8
        self._buffer = bytearray()
        self._mode_padding = mode_padding

    def _process_block(self) -> bytes:
        buffer_byte_len = len(self._buffer)
        if buffer_byte_len == 0:
            return b''

        #  缓冲区超过一个分组长度时，保留尾部不足或刚好一个分组长度的部分，输出前面的完整分组部分
        out_byte_len = ((buffer_byte_len - 1) // self._block_byte_len) * self._block_byte_len
        out_octets = bytes(memoryview(self._buffer)[0:out_byte_len])
        self._buffer = self._buffer[out_byte_len:]
        return out_octets

    def update(self, in_octets: Union[bytes, bytearray, memoryview]) -> bytes:
        self._buffer.extend(in_octets)
        return self._process_block()

    def finalize(self):
        buffer_byte_len = len(self._buffer)
        assert buffer_byte_len <= self._block_byte_len
        if self._mode_padding:
            padding_byte_len = self._block_byte_len - buffer_byte_len
            if padding_byte_len == 0:
                padding_byte_len = self._block_byte_len
            self._buffer.extend([padding_byte_len] * padding_byte_len)
            out_octets = bytes(self._buffer)
            self._buffer = None
            return bytes(out_octets)
        else:
            if buffer_byte_len != self._block_byte_len:
                raise PaddingException("经过填充的数据长度不是分组长度的整数倍"
                                       "/Length of padded data is not a multiple of block size")
            padding_len = self._buffer[-1]
            for i in range(-padding_len, 0):
                if self._buffer[i] != padding_len:
                    raise PaddingException("填充数据格式错误/Padded data is mal-formatted.")
            return self._buffer[0:-padding_len]


def pkcs7_pad(data: Union[bytes, bytearray, memoryview], block_size: int) -> bytes:
    """PKCS#7数据填充"""
    padding = PKCS7Padding(block_size, True)
    out_octets = bytearray(padding.update(data))
    out_octets.extend(padding.finalize())
    return out_octets


def pkcs7_unpad(data: Union[bytes, bytearray, memoryview], block_size: int) -> bytes:
    """PKCS#7数据反填充"""
    padding = PKCS7Padding(block_size, False)
    out_octets = bytearray(padding.update(data))
    out_octets.extend(padding.finalize())
    return out_octets


class OneAndZerosPadding(Codec):
    """ISO9797M2填充方法

    GB/T 15852.1-2020 (ISO/IEC 9797-1）中规定的填充方法2，与GB/T 17964-2021的C.3相同。
    也称为ISO7816-4填充方法，或者One-and-zeros填充方法。
    """

    def __init__(self, block_size: int, mode_padding):
        super().__init__()
        if not (0 < block_size < 2048):
            raise PaddingException('分组大小必须大于0小于2048/Block size should be between 0 and 2048 exclusive')
        if block_size % 8 != 0:
            raise PaddingException('分组大小必须为8的倍数/Block size should be a multiple of 8')
        self._block_size = block_size
        self._block_byte_len = block_size // 8
        self._buffer = bytearray()
        self._mode_padding = mode_padding

    def _process_block(self):
        buffer_byte_len = len(self._buffer)
        if buffer_byte_len == 0:
            return b''

        #  缓冲区超过一个分组长度时，保留尾部不足或刚好一个分组长度的部分，输出前面的完整分组部分
        out_byte_len = ((buffer_byte_len - 1) // self._block_byte_len) * self._block_byte_len
        out_octets = bytes(memoryview(self._buffer)[0:out_byte_len])
        self._buffer = self._buffer[out_byte_len:]
        return out_octets

    def update(self, in_octets: Union[bytes, bytearray, memoryview]):
        self._buffer.extend(in_octets)
        return self._process_block()

    def finalize(self):
        buffer_byte_len = len(self._buffer)
        assert buffer_byte_len <= self._block_byte_len
        if self._mode_padding:
            self._buffer.append(0x80)
            if buffer_byte_len == self._block_byte_len:
                self._buffer.extend(b'\x00' * (self._block_byte_len - 1))
                out_octets = bytes(self._buffer)
            else:
                padding_byte_len = self._block_byte_len - buffer_byte_len - 1
                self._buffer.extend([0] * padding_byte_len)
                out_octets = bytes(self._buffer)
            self._buffer = None
            return bytes(out_octets)
        else:
            if buffer_byte_len != self._block_byte_len:
                raise PaddingException("经过填充的数据长度不是分组长度的整数倍"
                                       "/Length of padded data is not a multiple of block size")
            for i in range(-1, -buffer_byte_len - 1, -1):
                if self._buffer[i] == 0x80:
                    return bytes(self._buffer[:i])
                elif self._buffer[i] != 0:
                    raise PaddingException("填充数据格式错误，填充部分有非0字节/"
                                           "Padded data is mal-formatted with non-zero padding byte.")
            else:
                raise PaddingException("填充数据格式错误，最后分组未找到0x80字节"
                                       "/Padded data is mal-formatted not ending with byte 0x80.")


def one_and_zeros_pad(data: Union[bytes, bytearray, memoryview], block_size: int) -> bytes:
    """ISO9797M2数据填充"""
    padding = OneAndZerosPadding(block_size, True)
    out_octets = bytearray(padding.update(data))
    out_octets.extend(padding.finalize())
    return bytes(out_octets)


def one_and_zeros_unpad(data: Union[bytes, bytearray, memoryview], block_size: int) -> bytes:
    """ISO9797M2数据反填充"""
    padding = OneAndZerosPadding(block_size, False)
    out_octets = bytearray(padding.update(data))
    out_octets.extend(padding.finalize())
    return bytes(out_octets)


class LengthPrefixedPadding(Codec):
    """ISO9797M3填充方法

    GB/T 15852.1-2020 (ISO/IEC 9797-1）中规定的填充方法3，也称为长度前缀数据填充方法。
    与GB/T 17964-2021的C.3描述相同，但示例有差别（猜想是GB/T 17964的错讹）。
    经改造加强可以适用于预先知道长度的非整数比特的情况，比如ASN.1的BITSTRING类型。
    """
    def __init__(self, block_size: int, mode_padding):
        super().__init__()
        if block_size % 8 != 0:
            raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8')
        self._block_size = block_size
        self._block_byte_len = block_size // 8
        self._buffer = bytearray()
        self._mode_padding = mode_padding
        self._empty_string = b'\x00' * (2 * self._block_byte_len)

    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        self._buffer.extend(octets)
        return b''

    def finalize(self) -> bytes:
        if self._mode_padding:
            buffer_byte_len = len(self._buffer)
            if buffer_byte_len == 0:
                return self._empty_string

            if buffer_byte_len >= (1 << self._block_size):
                raise ValueError('数据长度超出分组大小限制/Length of data exceeds the block size.')

            prefix = (buffer_byte_len * 8).to_bytes(self._block_byte_len, byteorder='big', signed=False)
            result = bytearray()
            result.extend(prefix)
            result.extend(self._buffer)
            if (residue := buffer_byte_len % self._block_byte_len) > 0:
                result.extend(b'\x00' * (self._block_byte_len - residue))
            return bytes(result)
        else:
            buffer_byte_len = len(self._buffer)
            if buffer_byte_len % self._block_byte_len != 0:
                raise PaddingException('数据填充后的长度应当为分组的整数倍/'
                                       'Padded data length should be a multiple of data block length.')
            if buffer_byte_len < 2 * self._block_byte_len:
                raise PaddingException('数据填充后的长度至少为2个分组/Padded data should be at lease 2 data blocks.')

            if self._buffer == self._empty_string:
                return b''

            data_byte_len = int.from_bytes(self._buffer[0:self._block_byte_len]) // 8
            block_count = (data_byte_len - 1) // self._block_byte_len + 2  # 头部1个分组，数据+填充至少1个分组

            if buffer_byte_len != block_count * self._block_byte_len:
                raise PaddingException('数据头的长度与数据实际长度不符/Data length does not match the prefix.')

            return bytes(self._buffer[self._block_byte_len:self._block_byte_len + data_byte_len])


def length_prefixed_pad(data: Union[bytes, bytearray], block_size: int) -> bytes:
    """ISO9797M3数据填充"""
    padding = LengthPrefixedPadding(block_size, True)
    out_octets = bytearray(padding.update(data))
    out_octets.extend(padding.finalize())
    return bytes(out_octets)


def length_prefixed_unpad(data: Union[bytes, bytearray], block_size: int) -> bytes:
    """ISO9797M3数据反填充"""
    padding = LengthPrefixedPadding(block_size, False)
    out_octets = bytearray(padding.update(data))
    out_octets.extend(padding.finalize())
    return bytes(out_octets)


class ZeroPadding(Codec):
    """ISO9797M1填充方法

    GB/T 15852.1-2020 (ISO/IEC 9797-1）中规定的填充方法1，也称为全0填充方法。
    """
    def __init__(self, block_size: int, mode_padding, padding_byte_len: Optional[int] = None):
        super().__init__()
        self._block_size = block_size
        assert self._block_size % 8 == 0
        self._block_byte_len = block_size // 8

        self._padding_byte_len = padding_byte_len
        assert self._padding_byte_len is None or self._padding_byte_len < self._block_size
        self._bytes_padded = None

        self._mode_padding = mode_padding
        self._empty_string = True
        self._buffer = bytearray()

    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        self._buffer.extend(octets)
        buffer_byte_len = len(self._buffer)
        if buffer_byte_len != 0:
            self._empty_string = False
        out_octets = bytearray()
        m = 0
        n = self._block_byte_len
        while n < buffer_byte_len:
            out_octets.extend(memoryview(self._buffer)[m:n])
            m = n
            n = m + self._block_byte_len
        self._buffer = self._buffer[m:]
        return bytes(out_octets)

    def finalize(self) -> bytes:
        buffer_byte_len = len(self._buffer)
        assert 0 <= buffer_byte_len <= self._block_byte_len

        if self._mode_padding:
            if self._empty_string:
                return b'\x00' * self._block_byte_len

            self._bytes_padded = self._block_byte_len - buffer_byte_len
            if self._padding_byte_len is not None and self._padding_byte_len != self._bytes_padded:
                raise ValueError()
            self._buffer.extend(b'\x00' * self._bytes_padded)
            return bytes(self._buffer)
        else:
            assert buffer_byte_len == self._block_byte_len
            if self._padding_byte_len is not None:
                for i in range(-1, -self._padding_byte_len - 1, -1):
                    if self._buffer[i] != 0x00:
                        raise PaddingException()
                return bytes(memoryview(self._buffer)[:-self._padding_byte_len])
            else:
                n = self._block_byte_len - 1
                while n >= 0:
                    if self._buffer[n] != 0x00:
                        break
                return bytes(memoryview(self._buffer)[0:n + 1])


def zero_pad(data: Union[bytes, bytearray], block_size: int) -> bytes:
    """ISO9797M1数据填充"""
    padding = ZeroPadding(block_size, True)
    out_octets = bytearray(padding.update(data))
    out_octets.extend(padding.finalize())
    return bytes(out_octets)


def zero_unpad(data: Union[bytes, bytearray], block_size: int) -> bytes:
    """ISO9797M1数据反填充"""
    padding = ZeroPadding(block_size, False)
    out_octets = bytearray(padding.update(data))
    out_octets.extend(padding.finalize())
    return bytes(out_octets)


def get_padding(padding_name: Optional[str], block_size: int, mode_padding: bool):
    padding_name = padding_name.upper()
    if padding_name is None:
        return None
    elif padding_name == 'PKCS7':
        return PKCS7Padding(block_size=block_size, mode_padding=mode_padding)
    elif padding_name == 'ISO7816-4' or padding_name == 'ISO9797M2' or padding_name == 'ONE_AND_ZEROS':
        return OneAndZerosPadding(block_size=block_size, mode_padding=mode_padding)
    elif padding_name == 'ISO9797M3' or padding_name == 'LENGTH_PREFIXED':
        return LengthPrefixedPadding(block_size=block_size, mode_padding=mode_padding)
    elif padding_name == 'ISO9797M1' or padding_name == 'ZERO':
        return ZeroPadding(block_size=block_size, mode_padding=mode_padding)
    else:
        raise ValueError(f'未知的填充方法/Unknown padding: {padding_name}')
