"""P22P v0.4 common functions and constants"""
import struct

# ===== IDs =====

ID_SERVER_COMMAND = "\x01"  # a command for the server
ID_CLIENT_COMMAND = "\x02"  # a command for another client
ID_DATA_FROM_HOST = "\x03"  # data from the side which is connected to
ID_DATA_FROM_CLIENT = "\x04"  # data from the side from which is connected


# ===== STRUCT FORMATS =====

BYTEORDER = "!"

LENGTH_FORMAT = "L"
CID_FORMAT = "H"
PORT_FORMAT = "H"


# ===== PRECALCULATED VALUES =====

LENGTH_FORMAT_LENGTH = struct.calcsize(LENGTH_FORMAT)
CID_FORMAT_LENGTH = struct.calcsize(CID_FORMAT)
MAX_CIDS = struct.unpack(BYTEORDER + CID_FORMAT, "\xff" * struct.calcsize(CID_FORMAT))[0]
DATA_PREFIX_LENGTH = struct.calcsize(CID_FORMAT + PORT_FORMAT)
PORT_LENGTH = struct.calcsize(PORT_FORMAT)

# ===== Constants =====

VERSION = "0.4" # REMEMBER: also change in setup.py
DEFAULT_PORT = 39453
DEFAULT_COMPRESSION_LEVEL = 3
DEFAULT_SERVER = "katzenhaus.club"


# ===== Exceptions =====

class CommunicationError(IOError):
    """Exception indicating a error during communication"""
    pass


class ConnectionError(IOError):
    """Exception indicating a error in the connection."""
    pass


class UsageError(Exception):
    """Exception indicating a usage error"""
    pass


class JoinFailed(Exception):
    """Exception indiaction that joining or creating a group failed."""
    pass

class ReservationFailed(Exception):
    """Exception indicating that reserving or extending a reservation failed"""
    pass


# ===== Encryption (uses CBC) =====

def _blockXOR(a, b):
    """returns a xor b"""
    if len(a) != len(b):
        raise ValueError("expected to strings with same length")
    res = []
    for i in xrange(len(a)):
        res.append(chr(ord(a[i]) ^ ord(b[i])))
    return "".join(res)


def encrypt(plain, key):
    """encrypt using CBC."""
    blocklength = len(key)
    dl = len(plain)
    bc = dl/blocklength
    v = key
    i = 0
    res = []
    while i < bc:
        start = i*blocklength
        end = start + blocklength
        block = plain[start:end]
        v = _blockXOR(block, v)
        i += 1
        res.append(v)
    rm = dl % blocklength
    if rm > 0:
        block = plain[-rm:]
        plain2 = _blockXOR(block, v[0:rm])
        res.append(plain2)
    return "".join(res)


def decrypt(chipher, key):
    """decrypts using CBC."""
    blocklength = len(key)
    dl = len(chipher)
    bc = dl/blocklength
    v = key
    i = 0
    res = []
    while i < bc:
        start = i * blocklength
        end = start + blocklength
        block = chipher[start:end]
        plain = _blockXOR(block, v)
        v = block
        i += 1
        res.append(plain)
    rm = dl % blocklength
    if rm > 0:
        block = chipher[-rm:]
        plain = _blockXOR(block, v[0:rm])
        res.append(plain)
    return "".join(res)
