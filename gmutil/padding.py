from typing import Union, Optional
from .commons import Codec


class PaddingException(Exception):

    def __init__(self, *args):
        super().__init__(*args)


class PKCS7Padding(Codec):
    """PKCS#7填充方法类。

    与GB/T 17964-2021 C.2相同。
    """

    def __init__(self, block_size: int, mode_padding: bool = True):
        super().__init__()
        if not (0 < block_size < 2048):
            raise PaddingException('分组大小必须大于0小于2048/Block size should be between 0 and 2048 exclusive')
        if block_size % 8 != 0:
            raise PaddingException('分组大小必须为8的倍数/Block size should be a multiple of 8')
        self._block_size = block_size
        self._block_byte_len = block_size // 8
        self._buffer = bytearray()
        self._mode_padding = mode_padding

    def update(self, in_octets: Union[bytes, bytearray, memoryview]) -> bytes:
        self._buffer.extend(in_octets)
        buffer_len = len(self._buffer)
        if buffer_len == 0:
            return b''

        if self._mode_padding:
            out_len = (buffer_len // self._block_byte_len) * self._block_byte_len
            out_octets = bytes(self._buffer[:out_len])
            self._buffer = self._buffer[out_len:]
            return out_octets
        else:
            out_len = ((buffer_len - 1) // self._block_byte_len - 1) * self._block_byte_len
            if out_len <= 0:
                return b''

            out_octets = bytes(self._buffer[:out_len])
            self._buffer = self._buffer[out_len:]
            return out_octets

    def finalize(self):
        if self._mode_padding:
            buffer_len = len(self._buffer)
            padding_byte_len = self._block_byte_len - buffer_len % self._block_byte_len
            self._buffer.extend([padding_byte_len] * padding_byte_len)
            out_octets = bytes(self._buffer)
            self._buffer = None
            return bytes(out_octets)
        else:
            if len(self._buffer) % self._block_byte_len != 0:
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

    def __init__(self, block_size: int, mode_padding: bool = True):
        super().__init__()
        if not (0 < block_size < 2048):
            raise PaddingException('分组大小必须大于0小于2048/Block size should be between 0 and 2048 exclusive')
        if block_size % 8 != 0:
            raise PaddingException('分组大小必须为8的倍数/Block size should be a multiple of 8')
        self._block_size = block_size
        self._block_byte_len = block_size // 8
        self._buffer = bytearray()
        self._mode_padding = mode_padding

    def update(self, in_octets: Union[bytes, bytearray, memoryview]):
        self._buffer.extend(in_octets)
        buffer_len = len(self._buffer)
        if buffer_len == 0:
            return b''

        if self._mode_padding:
            out_len = (buffer_len // self._block_byte_len) * self._block_byte_len
            out_octets = bytes(self._buffer[:out_len])
            self._buffer = self._buffer[out_len:]
            return out_octets
        else:
            out_len = ((buffer_len - 1) // self._block_byte_len) * self._block_byte_len
            if out_len <= 0:
                return b''

            out_octets = bytes(self._buffer[:out_len])
            self._buffer = self._buffer[out_len:]
            return out_octets

    def finalize(self):
        if self._mode_padding:
            self._buffer.append(0x80)
            buffer_len = len(self._buffer)
            padding_byte_len = self._block_byte_len - buffer_len % self._block_byte_len
            self._buffer.extend([0] * padding_byte_len)
            out_octets = bytes(self._buffer)
            self._buffer = None
            return bytes(out_octets)
        else:
            buffer_len = len(self._buffer)
            if buffer_len % self._block_byte_len != 0:
                raise PaddingException("经过填充的数据长度不是分组长度的整数倍"
                                       "/Length of padded data is not a multiple of block size")
            for i in range(-1, -buffer_len - 1, -1):
                if self._buffer[i] == 0x80:
                    return bytes(self._buffer[:i])
            else:
                raise PaddingException("填充数据格式错误/Padded data is mal-formatted.")


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
    def __init__(self, block_size: int, mode_padding: bool = True):
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


def get_padding(name: Optional[str], block_size: int):
    if name is None:
        return None
    elif name == 'pkcs7':
        return PKCS7Padding(block_size=block_size)
    elif name == 'iso7816-4' or name == 'iso9797m2' or name == 'one-and-zeros':
        return OneAndZerosPadding(block_size=block_size)
    elif name == 'iso9797m3' or name == 'length-prefixed':
        return LengthPrefixedPadding(block_size=block_size)
    else:
        raise ValueError(f'未知的填充方法/Unknown padding: {name}')
