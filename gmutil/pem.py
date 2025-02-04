import re
import base64
from io import StringIO, TextIOBase
from typing import Union, TextIO

_PEM_BEGIN_BOUNDARY_PATTERN = re.compile(r'-+BEGIN (\w+)-+')
_PEM_END_BOUNDARY_PATTERN = re.compile(r'-+END (\w+)-+')

class PemFileFormatException(Exception):
    def __init__(self, *args):
        super().__init__(*args)

class PemFile:
    def __init__(self):
        self._parts = []

    @property
    def items(self):
        return self._parts

    @staticmethod
    def load(source: Union[str, TextIOBase]):
        def read_source(src: Union[TextIOBase, TextIO]):
            name = None
            buffer = None
            result = []
            for line in src:
                line = line.strip()
                if m := _PEM_BEGIN_BOUNDARY_PATTERN.match(line):
                    if name is not None:
                        raise PemFileFormatException(name, buffer)
                    else:
                        name = m.group(1)
                        buffer = StringIO()
                        continue
                if m := _PEM_END_BOUNDARY_PATTERN.match(line):
                    if name is None or name != m.group(1):
                        raise PemFileFormatException()
                    else:
                        data = base64.standard_b64decode(buffer.getvalue())
                        result.append((name, data))
                        name = None
                        buffer = None
                        continue
                if len(line) == 0 or line[0] == '#':
                    continue

                buffer.write(line)
            return result

        pem = PemFile()
        if isinstance(source, str):
            with open(source, 'r', encoding='iso-8859-1') as src_file:
                pem._parts = read_source(src_file)
        else:
            pem._parts = read_source(source)
        return pem
