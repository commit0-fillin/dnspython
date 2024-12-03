"""DNS rdata."""
import base64
import binascii
import inspect
import io
import itertools
import random
from importlib import import_module
from typing import Any, Dict, Optional, Tuple, Union
import dns.exception
import dns.immutable
import dns.ipv4
import dns.ipv6
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer
import dns.ttl
import dns.wire
_chunksize = 32
_allow_relative_comparisons = True

class NoRelativeRdataOrdering(dns.exception.DNSException):
    """An attempt was made to do an ordered comparison of one or more
    rdata with relative names.  The only reliable way of sorting rdata
    is to use non-relativized rdata.

    """

def _wordbreak(data, chunksize=_chunksize, separator=b' '):
    """Break a binary string into chunks of chunksize characters separated by
    a space.
    """
    return separator.join(data[i:i+chunksize] for i in range(0, len(data), chunksize))

def _hexify(data, chunksize=_chunksize, separator=b' ', **kw):
    """Convert a binary string into its hex encoding, broken up into chunks
    of chunksize characters separated by a separator.
    """
    hex_data = binascii.hexlify(data)
    return _wordbreak(hex_data, chunksize, separator)

def _base64ify(data, chunksize=_chunksize, separator=b' ', **kw):
    """Convert a binary string into its base64 encoding, broken up into chunks
    of chunksize characters separated by a separator.
    """
    b64_data = base64.b64encode(data)
    return _wordbreak(b64_data, chunksize, separator)
__escaped = b'"\\'

def _escapify(qstring):
    """Escape the characters in a quoted string which need it."""
    text = qstring.decode('ascii')
    return ''.join(('\\' + c if c in __escaped else c) for c in text)

def _truncate_bitmap(what):
    """Determine the index of greatest byte that isn't all zeros, and
    return the bitmap that contains all the bytes less than that index.
    """
    for i in range(len(what) - 1, -1, -1):
        if what[i] != 0:
            return what[:i+1]
    return b''
_constify = dns.immutable.constify

@dns.immutable.immutable
class Rdata:
    """Base class for all DNS rdata types."""
    __slots__ = ['rdclass', 'rdtype', 'rdcomment']

    def __init__(self, rdclass, rdtype):
        """Initialize an rdata.

        *rdclass*, an ``int`` is the rdataclass of the Rdata.

        *rdtype*, an ``int`` is the rdatatype of the Rdata.
        """
        self.rdclass = self._as_rdataclass(rdclass)
        self.rdtype = self._as_rdatatype(rdtype)
        self.rdcomment = None

    def __getstate__(self):
        state = {}
        for slot in self._get_all_slots():
            state[slot] = getattr(self, slot)
        return state

    def __setstate__(self, state):
        for slot, val in state.items():
            object.__setattr__(self, slot, val)
        if not hasattr(self, 'rdcomment'):
            object.__setattr__(self, 'rdcomment', None)

    def covers(self) -> dns.rdatatype.RdataType:
        """Return the type a Rdata covers.

        DNS SIG/RRSIG rdatas apply to a specific type; this type is
        returned by the covers() function.  If the rdata type is not
        SIG or RRSIG, dns.rdatatype.NONE is returned.  This is useful when
        creating rdatasets, allowing the rdataset to contain only RRSIGs
        of a particular type, e.g. RRSIG(NS).

        Returns a ``dns.rdatatype.RdataType``.
        """
        return dns.rdatatype.NONE

    def extended_rdatatype(self) -> int:
        """Return a 32-bit type value, the least significant 16 bits of
        which are the ordinary DNS type, and the upper 16 bits of which are
        the "covered" type, if any.

        Returns an ``int``.
        """
        pass

    def to_text(self, origin: Optional[dns.name.Name]=None, relativize: bool=True, **kw: Dict[str, Any]) -> str:
        """Convert an rdata to text format.

        Returns a ``str``.
        """
        pass

    def to_wire(self, file: Optional[Any]=None, compress: Optional[dns.name.CompressType]=None, origin: Optional[dns.name.Name]=None, canonicalize: bool=False) -> bytes:
        """Convert an rdata to wire format.

        Returns a ``bytes`` or ``None``.
        """
        pass

    def to_generic(self, origin: Optional[dns.name.Name]=None) -> 'dns.rdata.GenericRdata':
        """Creates a dns.rdata.GenericRdata equivalent of this rdata.

        Returns a ``dns.rdata.GenericRdata``.
        """
        pass

    def to_digestable(self, origin: Optional[dns.name.Name]=None) -> bytes:
        """Convert rdata to a format suitable for digesting in hashes.  This
        is also the DNSSEC canonical form.

        Returns a ``bytes``.
        """
        pass

    def __repr__(self):
        covers = self.covers()
        if covers == dns.rdatatype.NONE:
            ctext = ''
        else:
            ctext = '(' + dns.rdatatype.to_text(covers) + ')'
        return '<DNS ' + dns.rdataclass.to_text(self.rdclass) + ' ' + dns.rdatatype.to_text(self.rdtype) + ctext + ' rdata: ' + str(self) + '>'

    def __str__(self):
        return self.to_text()

    def _cmp(self, other):
        """Compare an rdata with another rdata of the same rdtype and
        rdclass.

        For rdata with only absolute names:
            Return < 0 if self < other in the DNSSEC ordering, 0 if self
            == other, and > 0 if self > other.
        For rdata with at least one relative names:
            The rdata sorts before any rdata with only absolute names.
            When compared with another relative rdata, all names are
            made absolute as if they were relative to the root, as the
            proper origin is not available.  While this creates a stable
            ordering, it is NOT guaranteed to be the DNSSEC ordering.
            In the future, all ordering comparisons for rdata with
            relative names will be disallowed.
        """
        pass

    def __eq__(self, other):
        if not isinstance(other, Rdata):
            return False
        if self.rdclass != other.rdclass or self.rdtype != other.rdtype:
            return False
        our_relative = False
        their_relative = False
        try:
            our = self.to_digestable()
        except dns.name.NeedAbsoluteNameOrOrigin:
            our = self.to_digestable(dns.name.root)
            our_relative = True
        try:
            their = other.to_digestable()
        except dns.name.NeedAbsoluteNameOrOrigin:
            their = other.to_digestable(dns.name.root)
            their_relative = True
        if our_relative != their_relative:
            return False
        return our == their

    def __ne__(self, other):
        if not isinstance(other, Rdata):
            return True
        if self.rdclass != other.rdclass or self.rdtype != other.rdtype:
            return True
        return not self.__eq__(other)

    def __lt__(self, other):
        if not isinstance(other, Rdata) or self.rdclass != other.rdclass or self.rdtype != other.rdtype:
            return NotImplemented
        return self._cmp(other) < 0

    def __le__(self, other):
        if not isinstance(other, Rdata) or self.rdclass != other.rdclass or self.rdtype != other.rdtype:
            return NotImplemented
        return self._cmp(other) <= 0

    def __ge__(self, other):
        if not isinstance(other, Rdata) or self.rdclass != other.rdclass or self.rdtype != other.rdtype:
            return NotImplemented
        return self._cmp(other) >= 0

    def __gt__(self, other):
        if not isinstance(other, Rdata) or self.rdclass != other.rdclass or self.rdtype != other.rdtype:
            return NotImplemented
        return self._cmp(other) > 0

    def __hash__(self):
        return hash(self.to_digestable(dns.name.root))

    def replace(self, **kwargs: Any) -> 'Rdata':
        """
        Create a new Rdata instance based on the instance replace was
        invoked on. It is possible to pass different parameters to
        override the corresponding properties of the base Rdata.

        Any field specific to the Rdata type can be replaced, but the
        *rdtype* and *rdclass* fields cannot.

        Returns an instance of the same Rdata subclass as *self*.
        """
        pass

@dns.immutable.immutable
class GenericRdata(Rdata):
    """Generic Rdata Class

    This class is used for rdata types for which we have no better
    implementation.  It implements the DNS "unknown RRs" scheme.
    """
    __slots__ = ['data']

    def __init__(self, rdclass, rdtype, data):
        super().__init__(rdclass, rdtype)
        self.data = data
_rdata_classes: Dict[Tuple[dns.rdataclass.RdataClass, dns.rdatatype.RdataType], Any] = {}
_module_prefix = 'dns.rdtypes'

def from_text(rdclass: Union[dns.rdataclass.RdataClass, str], rdtype: Union[dns.rdatatype.RdataType, str], tok: Union[dns.tokenizer.Tokenizer, str], origin: Optional[dns.name.Name]=None, relativize: bool=True, relativize_to: Optional[dns.name.Name]=None, idna_codec: Optional[dns.name.IDNACodec]=None) -> Rdata:
    """Build an rdata object from text format.

    This function attempts to dynamically load a class which
    implements the specified rdata class and type.  If there is no
    class-and-type-specific implementation, the GenericRdata class
    is used.

    Once a class is chosen, its from_text() class method is called
    with the parameters to this function.

    If *tok* is a ``str``, then a tokenizer is created and the string
    is used as its input.

    *rdclass*, a ``dns.rdataclass.RdataClass`` or ``str``, the rdataclass.

    *rdtype*, a ``dns.rdatatype.RdataType`` or ``str``, the rdatatype.

    *tok*, a ``dns.tokenizer.Tokenizer`` or a ``str``.

    *origin*, a ``dns.name.Name`` (or ``None``), the
    origin to use for relative names.

    *relativize*, a ``bool``.  If true, name will be relativized.

    *relativize_to*, a ``dns.name.Name`` (or ``None``), the origin to use
    when relativizing names.  If not set, the *origin* value will be used.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder to use if a tokenizer needs to be created.  If
    ``None``, the default IDNA 2003 encoder/decoder is used.  If a
    tokenizer is not created, then the codec associated with the tokenizer
    is the one that is used.

    Returns an instance of the chosen Rdata subclass.

    """
    pass

def from_wire_parser(rdclass: Union[dns.rdataclass.RdataClass, str], rdtype: Union[dns.rdatatype.RdataType, str], parser: dns.wire.Parser, origin: Optional[dns.name.Name]=None) -> Rdata:
    """Build an rdata object from wire format

    This function attempts to dynamically load a class which
    implements the specified rdata class and type.  If there is no
    class-and-type-specific implementation, the GenericRdata class
    is used.

    Once a class is chosen, its from_wire() class method is called
    with the parameters to this function.

    *rdclass*, a ``dns.rdataclass.RdataClass`` or ``str``, the rdataclass.

    *rdtype*, a ``dns.rdatatype.RdataType`` or ``str``, the rdatatype.

    *parser*, a ``dns.wire.Parser``, the parser, which should be
    restricted to the rdata length.

    *origin*, a ``dns.name.Name`` (or ``None``).  If not ``None``,
    then names will be relativized to this origin.

    Returns an instance of the chosen Rdata subclass.
    """
    pass

def from_wire(rdclass: Union[dns.rdataclass.RdataClass, str], rdtype: Union[dns.rdatatype.RdataType, str], wire: bytes, current: int, rdlen: int, origin: Optional[dns.name.Name]=None) -> Rdata:
    """Build an rdata object from wire format

    This function attempts to dynamically load a class which
    implements the specified rdata class and type.  If there is no
    class-and-type-specific implementation, the GenericRdata class
    is used.

    Once a class is chosen, its from_wire() class method is called
    with the parameters to this function.

    *rdclass*, an ``int``, the rdataclass.

    *rdtype*, an ``int``, the rdatatype.

    *wire*, a ``bytes``, the wire-format message.

    *current*, an ``int``, the offset in wire of the beginning of
    the rdata.

    *rdlen*, an ``int``, the length of the wire-format rdata

    *origin*, a ``dns.name.Name`` (or ``None``).  If not ``None``,
    then names will be relativized to this origin.

    Returns an instance of the chosen Rdata subclass.
    """
    pass

class RdatatypeExists(dns.exception.DNSException):
    """DNS rdatatype already exists."""
    supp_kwargs = {'rdclass', 'rdtype'}
    fmt = 'The rdata type with class {rdclass:d} and rdtype {rdtype:d} ' + 'already exists.'

def register_type(implementation: Any, rdtype: int, rdtype_text: str, is_singleton: bool=False, rdclass: dns.rdataclass.RdataClass=dns.rdataclass.IN) -> None:
    """Dynamically register a module to handle an rdatatype.

    *implementation*, a module implementing the type in the usual dnspython
    way.

    *rdtype*, an ``int``, the rdatatype to register.

    *rdtype_text*, a ``str``, the textual form of the rdatatype.

    *is_singleton*, a ``bool``, indicating if the type is a singleton (i.e.
    RRsets of the type can have only one member.)

    *rdclass*, the rdataclass of the type, or ``dns.rdataclass.ANY`` if
    it applies to all classes.
    """
    pass
