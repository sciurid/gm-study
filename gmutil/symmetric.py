from .commons import Codec, BlockCipherAlgorithm
from .padding import *
from .mode import *
from typing import Union, Literal

class SymmetricCipher:
    def __init__(self, algorithm: BlockCipherAlgorithm, mode: Mode, padding: Codec):
        pass

