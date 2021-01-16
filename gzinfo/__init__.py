import gzip
import struct

from dataclasses import dataclass
from typing import Optional


@dataclass
class GzInfo(object):
    fname: str
    method: int
    flag: int
    last_mtime: int


def read_gz_info(filename: str=None, fileobj=None, default_filename: str=None) -> Optional[GzInfo]:
    """Reading headers of GzipFile and returning fname."""
    if filename:
        _gz = gzip.GzipFile(filename)
        _fp = _gz.fileobj
    elif fileobj:
        _fp = fileobj
    else:
        raise NotImplementedError('Either filename or fileobj must be supplied')

    # the magic 2 bytes: if 0x1f 0x8b (037 213 in octal)
    magic = _fp.read(2)
    if magic == b'':
        _fp.seek(0)
        return None

    if magic != b'\037\213':
        raise OSError('Not a gzipped file (%r)' % magic)

    (method, flag, last_mtime) = struct.unpack("<BBIxx", _read_exact(_fp, 8))
    if method != 8:
        raise OSError('Unknown compression method')

    # Case where the name is not in the header according to flag
    if not flag & gzip.FNAME:
        # Not stored in the header, use the filename sans .gz
        if hasattr(_fp, 'name'):
            fname = _fp.name
        else:
            fname = default_filename
        _fp.seek(0)
        return GzInfo(
            fname=fname[:-3] if fname.endswith('.gzip') else fname,
            method=method,
            flag=flag,
            last_mtime=last_mtime)

    if flag & gzip.FEXTRA:
        # Read & discard the extra field, if present
        extra_len, = struct.unpack("<H", _read_exact(_fp, 2))
        _read_exact(_fp, extra_len)

    _fname = []  # bytes for fname
    if flag & gzip.FNAME:
        # Read a null-terminated string containing the filename
        # RFC 1952 <https://tools.ietf.org/html/rfc1952>
        #    specifies FNAME is encoded in latin1
        while True:
            s = _fp.read(1)
            if not s or s == b'\000':
                break
            _fname.append(s)
        _fp.seek(0)
        return GzInfo(
            fname=''.join([s.decode('latin1') for s in _fname]),
            method=method,
            flag=flag,
            last_mtime=last_mtime)


def _read_exact(fp, n):
    """This is the gzip.GzipFile._read_exact() method from the
    Python library.
    """
    data = fp.read(n)
    while len(data) < n:
        b = fp.read(n - len(data))
        if not b:
            raise EOFError("Compressed file ended before the "
                           "end-of-stream marker was reached")
        data += b
    return data