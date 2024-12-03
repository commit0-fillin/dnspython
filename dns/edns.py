"""EDNS Options"""
import binascii
import math
import socket
import struct
from typing import Any, Dict, Optional, Union
import dns.enum
import dns.inet
import dns.rdata
import dns.wire

class OptionType(dns.enum.IntEnum):
    NSID = 3
    DAU = 5
    DHU = 6
    N3U = 7
    ECS = 8
    EXPIRE = 9
    COOKIE = 10
    KEEPALIVE = 11
    PADDING = 12
    CHAIN = 13
    EDE = 15

class Option:
    """Base class for all EDNS option types."""

    def __init__(self, otype: Union[OptionType, str]):
        """Initialize an option.

        *otype*, a ``dns.edns.OptionType``, is the option type.
        """
        self.otype = OptionType.make(otype)

    def to_wire(self, file: Optional[Any]=None) -> Optional[bytes]:
        """Convert an option to wire format.

        Returns a ``bytes`` or ``None``.

        """
        data = self._to_wire()
        if file:
            file.write(struct.pack('!HH', self.otype, len(data)))
            file.write(data)
            return None
        else:
            return struct.pack('!HH', self.otype, len(data)) + data

    @classmethod
    def from_wire_parser(cls, otype: OptionType, parser: 'dns.wire.Parser') -> 'Option':
        """Build an EDNS option object from wire format.

        *otype*, a ``dns.edns.OptionType``, is the option type.

        *parser*, a ``dns.wire.Parser``, the parser, which should be
        restructed to the option length.

        Returns a ``dns.edns.Option``.
        """
        return cls(otype, parser.get_remaining())

    def _cmp(self, other):
        """Compare an EDNS option with another option of the same type.

        Returns < 0 if < *other*, 0 if == *other*, and > 0 if > *other*.
        """
        wire = self.to_wire()
        other_wire = other.to_wire()
        return (wire > other_wire) - (wire < other_wire)

    def __eq__(self, other):
        if not isinstance(other, Option):
            return False
        if self.otype != other.otype:
            return False
        return self._cmp(other) == 0

    def __ne__(self, other):
        if not isinstance(other, Option):
            return True
        if self.otype != other.otype:
            return True
        return self._cmp(other) != 0

    def __lt__(self, other):
        if not isinstance(other, Option) or self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) < 0

    def __le__(self, other):
        if not isinstance(other, Option) or self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) <= 0

    def __ge__(self, other):
        if not isinstance(other, Option) or self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) >= 0

    def __gt__(self, other):
        if not isinstance(other, Option) or self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) > 0

    def __str__(self):
        return self.to_text()

class GenericOption(Option):
    """Generic Option Class

    This class is used for EDNS option types for which we have no better
    implementation.
    """

    def __init__(self, otype: Union[OptionType, str], data: Union[bytes, str]):
        super().__init__(otype)
        self.data = dns.rdata.Rdata._as_bytes(data, True)

class ECSOption(Option):
    """EDNS Client Subnet (ECS, RFC7871)"""

    def __init__(self, address: str, srclen: Optional[int]=None, scopelen: int=0):
        """*address*, a ``str``, is the client address information.

        *srclen*, an ``int``, the source prefix length, which is the
        leftmost number of bits of the address to be used for the
        lookup.  The default is 24 for IPv4 and 56 for IPv6.

        *scopelen*, an ``int``, the scope prefix length.  This value
        must be 0 in queries, and should be set in responses.
        """
        super().__init__(OptionType.ECS)
        af = dns.inet.af_for_address(address)
        if af == socket.AF_INET6:
            self.family = 2
            if srclen is None:
                srclen = 56
            address = dns.rdata.Rdata._as_ipv6_address(address)
            srclen = dns.rdata.Rdata._as_int(srclen, 0, 128)
            scopelen = dns.rdata.Rdata._as_int(scopelen, 0, 128)
        elif af == socket.AF_INET:
            self.family = 1
            if srclen is None:
                srclen = 24
            address = dns.rdata.Rdata._as_ipv4_address(address)
            srclen = dns.rdata.Rdata._as_int(srclen, 0, 32)
            scopelen = dns.rdata.Rdata._as_int(scopelen, 0, 32)
        else:
            raise ValueError('Bad address family')
        assert srclen is not None
        self.address = address
        self.srclen = srclen
        self.scopelen = scopelen
        addrdata = dns.inet.inet_pton(af, address)
        nbytes = int(math.ceil(srclen / 8.0))
        self.addrdata = addrdata[:nbytes]
        nbits = srclen % 8
        if nbits != 0:
            last = struct.pack('B', ord(self.addrdata[-1:]) & 255 << 8 - nbits)
            self.addrdata = self.addrdata[:-1] + last

    @staticmethod
    def from_text(text: str) -> Option:
        """Convert a string into a `dns.edns.ECSOption`

        *text*, a `str`, the text form of the option.

        Returns a `dns.edns.ECSOption`.

        Examples:

        >>> import dns.edns
        >>>
        >>> # basic example
        >>> dns.edns.ECSOption.from_text('1.2.3.4/24')
        >>>
        >>> # also understands scope
        >>> dns.edns.ECSOption.from_text('1.2.3.4/24/32')
        >>>
        >>> # IPv6
        >>> dns.edns.ECSOption.from_text('2001:4b98::1/64/64')
        >>>
        >>> # it understands results from `dns.edns.ECSOption.to_text()`
        >>> dns.edns.ECSOption.from_text('ECS 1.2.3.4/24/32')
        """
        parts = text.split()
        if parts[0].upper() == 'ECS':
            parts = parts[1:]
        if len(parts) < 1 or len(parts) > 2:
            raise dns.exception.SyntaxError('Invalid ECS option format')
        
        address, srclen = parts[0].split('/', 1)
        if len(parts) == 2:
            scopelen = int(parts[1])
        else:
            scopelen = 0

        srclen = int(srclen)
        return ECSOption(address, srclen, scopelen)

class EDECode(dns.enum.IntEnum):
    OTHER = 0
    UNSUPPORTED_DNSKEY_ALGORITHM = 1
    UNSUPPORTED_DS_DIGEST_TYPE = 2
    STALE_ANSWER = 3
    FORGED_ANSWER = 4
    DNSSEC_INDETERMINATE = 5
    DNSSEC_BOGUS = 6
    SIGNATURE_EXPIRED = 7
    SIGNATURE_NOT_YET_VALID = 8
    DNSKEY_MISSING = 9
    RRSIGS_MISSING = 10
    NO_ZONE_KEY_BIT_SET = 11
    NSEC_MISSING = 12
    CACHED_ERROR = 13
    NOT_READY = 14
    BLOCKED = 15
    CENSORED = 16
    FILTERED = 17
    PROHIBITED = 18
    STALE_NXDOMAIN_ANSWER = 19
    NOT_AUTHORITATIVE = 20
    NOT_SUPPORTED = 21
    NO_REACHABLE_AUTHORITY = 22
    NETWORK_ERROR = 23
    INVALID_DATA = 24

class EDEOption(Option):
    """Extended DNS Error (EDE, RFC8914)"""
    _preserve_case = {'DNSKEY', 'DS', 'DNSSEC', 'RRSIGs', 'NSEC', 'NXDOMAIN'}

    def __init__(self, code: Union[EDECode, str], text: Optional[str]=None):
        """*code*, a ``dns.edns.EDECode`` or ``str``, the info code of the
        extended error.

        *text*, a ``str`` or ``None``, specifying additional information about
        the error.
        """
        super().__init__(OptionType.EDE)
        self.code = EDECode.make(code)
        if text is not None and (not isinstance(text, str)):
            raise ValueError('text must be string or None')
        self.text = text

class NSIDOption(Option):

    def __init__(self, nsid: bytes):
        super().__init__(OptionType.NSID)
        self.nsid = nsid
_type_to_class: Dict[OptionType, Any] = {OptionType.ECS: ECSOption, OptionType.EDE: EDEOption, OptionType.NSID: NSIDOption}

def get_option_class(otype: OptionType) -> Any:
    """Return the class for the specified option type.

    The GenericOption class is used if a more specific class is not
    known.
    """
    return _type_to_class.get(otype, GenericOption)

def option_from_wire_parser(otype: Union[OptionType, str], parser: 'dns.wire.Parser') -> Option:
    """Build an EDNS option object from wire format.

    *otype*, an ``int``, is the option type.

    *parser*, a ``dns.wire.Parser``, the parser, which should be
    restricted to the option length.

    Returns an instance of a subclass of ``dns.edns.Option``.
    """
    otype = OptionType.make(otype)
    cls = get_option_class(otype)
    return cls.from_wire_parser(otype, parser)

def option_from_wire(otype: Union[OptionType, str], wire: bytes, current: int, olen: int) -> Option:
    """Build an EDNS option object from wire format.

    *otype*, an ``int``, is the option type.

    *wire*, a ``bytes``, is the wire-format message.

    *current*, an ``int``, is the offset in *wire* of the beginning
    of the rdata.

    *olen*, an ``int``, is the length of the wire-format option data

    Returns an instance of a subclass of ``dns.edns.Option``.
    """
    otype = OptionType.make(otype)
    cls = get_option_class(otype)
    parser = dns.wire.Parser(wire, current)
    with parser.restrict_to(olen):
        return cls.from_wire_parser(otype, parser)

def register_type(implementation: Any, otype: OptionType) -> None:
    """Register the implementation of an option type.

    *implementation*, a ``class``, is a subclass of ``dns.edns.Option``.

    *otype*, an ``int``, is the option type.
    """
    _type_to_class[OptionType.make(otype)] = implementation
NSID = OptionType.NSID
DAU = OptionType.DAU
DHU = OptionType.DHU
N3U = OptionType.N3U
ECS = OptionType.ECS
EXPIRE = OptionType.EXPIRE
COOKIE = OptionType.COOKIE
KEEPALIVE = OptionType.KEEPALIVE
PADDING = OptionType.PADDING
CHAIN = OptionType.CHAIN
EDE = OptionType.EDE
