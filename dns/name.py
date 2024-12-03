"""DNS Names.
"""
import copy
import encodings.idna
import functools
import struct
from typing import Any, Callable, Dict, Iterable, Optional, Tuple, Union
import dns._features
import dns.enum
import dns.exception
import dns.immutable
import dns.wire
if dns._features.have('idna'):
    import idna
    have_idna_2008 = True
else:
    have_idna_2008 = False
CompressType = Dict['Name', int]

class NameRelation(dns.enum.IntEnum):
    """Name relation result from fullcompare()."""
    NONE = 0
    SUPERDOMAIN = 1
    SUBDOMAIN = 2
    EQUAL = 3
    COMMONANCESTOR = 4
NAMERELN_NONE = NameRelation.NONE
NAMERELN_SUPERDOMAIN = NameRelation.SUPERDOMAIN
NAMERELN_SUBDOMAIN = NameRelation.SUBDOMAIN
NAMERELN_EQUAL = NameRelation.EQUAL
NAMERELN_COMMONANCESTOR = NameRelation.COMMONANCESTOR

class EmptyLabel(dns.exception.SyntaxError):
    """A DNS label is empty."""

class BadEscape(dns.exception.SyntaxError):
    """An escaped code in a text format of DNS name is invalid."""

class BadPointer(dns.exception.FormError):
    """A DNS compression pointer points forward instead of backward."""

class BadLabelType(dns.exception.FormError):
    """The label type in DNS name wire format is unknown."""

class NeedAbsoluteNameOrOrigin(dns.exception.DNSException):
    """An attempt was made to convert a non-absolute name to
    wire when there was also a non-absolute (or missing) origin."""

class NameTooLong(dns.exception.FormError):
    """A DNS name is > 255 octets long."""

class LabelTooLong(dns.exception.SyntaxError):
    """A DNS label is > 63 octets long."""

class AbsoluteConcatenation(dns.exception.DNSException):
    """An attempt was made to append anything other than the
    empty name to an absolute DNS name."""

class NoParent(dns.exception.DNSException):
    """An attempt was made to get the parent of the root name
    or the empty name."""

class NoIDNA2008(dns.exception.DNSException):
    """IDNA 2008 processing was requested but the idna module is not
    available."""

class IDNAException(dns.exception.DNSException):
    """IDNA processing raised an exception."""
    supp_kwargs = {'idna_exception'}
    fmt = 'IDNA processing exception: {idna_exception}'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class NeedSubdomainOfOrigin(dns.exception.DNSException):
    """An absolute name was provided that is not a subdomain of the specified origin."""
_escaped = b'"().;\\@$'
_escaped_text = '"().;\\@$'

def _escapify(label: Union[bytes, str]) -> str:
    """Escape the characters in label which need it.
    @returns: the escaped string
    @rtype: string"""
    text = label.decode('ascii') if isinstance(label, bytes) else label
    escaped = ''
    for c in text:
        if c in _escaped_text:
            escaped += '\\' + c
        elif ord(c) >= 0x20 and ord(c) < 0x7F:
            escaped += c
        else:
            escaped += '\\%03d' % ord(c)
    return escaped

class IDNACodec:
    """Abstract base class for IDNA encoder/decoders."""

    def __init__(self):
        pass

class IDNA2003Codec(IDNACodec):
    """IDNA 2003 encoder/decoder."""

    def __init__(self, strict_decode: bool=False):
        """Initialize the IDNA 2003 encoder/decoder.

        *strict_decode* is a ``bool``. If `True`, then IDNA2003 checking
        is done when decoding.  This can cause failures if the name
        was encoded with IDNA2008.  The default is `False`.
        """
        super().__init__()
        self.strict_decode = strict_decode

    def encode(self, label: str) -> bytes:
        """Encode *label*."""
        return encodings.idna.ToASCII(label)

    def decode(self, label: bytes) -> str:
        """Decode *label*."""
        try:
            return encodings.idna.ToUnicode(label.decode('ascii'))
        except UnicodeError:
            if self.strict_decode:
                raise
            return label.decode('ascii', 'ignore')

class IDNA2008Codec(IDNACodec):
    """IDNA 2008 encoder/decoder."""

    def __init__(self, uts_46: bool=False, transitional: bool=False, allow_pure_ascii: bool=False, strict_decode: bool=False):
        """Initialize the IDNA 2008 encoder/decoder.

        *uts_46* is a ``bool``.  If True, apply Unicode IDNA
        compatibility processing as described in Unicode Technical
        Standard #46 (https://unicode.org/reports/tr46/).
        If False, do not apply the mapping.  The default is False.

        *transitional* is a ``bool``: If True, use the
        "transitional" mode described in Unicode Technical Standard
        #46.  The default is False.

        *allow_pure_ascii* is a ``bool``.  If True, then a label which
        consists of only ASCII characters is allowed.  This is less
        strict than regular IDNA 2008, but is also necessary for mixed
        names, e.g. a name with starting with "_sip._tcp." and ending
        in an IDN suffix which would otherwise be disallowed.  The
        default is False.

        *strict_decode* is a ``bool``: If True, then IDNA2008 checking
        is done when decoding.  This can cause failures if the name
        was encoded with IDNA2003.  The default is False.
        """
        super().__init__()
        self.uts_46 = uts_46
        self.transitional = transitional
        self.allow_pure_ascii = allow_pure_ascii
        self.strict_decode = strict_decode
IDNA_2003_Practical = IDNA2003Codec(False)
IDNA_2003_Strict = IDNA2003Codec(True)
IDNA_2003 = IDNA_2003_Practical
IDNA_2008_Practical = IDNA2008Codec(True, False, True, False)
IDNA_2008_UTS_46 = IDNA2008Codec(True, False, False, False)
IDNA_2008_Strict = IDNA2008Codec(False, False, False, True)
IDNA_2008_Transitional = IDNA2008Codec(True, True, False, False)
IDNA_2008 = IDNA_2008_Practical

def _validate_labels(labels: Tuple[bytes, ...]) -> None:
    """Check for empty labels in the middle of a label sequence,
    labels that are too long, and for too many labels.

    Raises ``dns.name.NameTooLong`` if the name as a whole is too long.

    Raises ``dns.name.EmptyLabel`` if a label is empty (i.e. the root
    label) and appears in a position other than the end of the label
    sequence

    """
    total_length = sum(len(label) + 1 for label in labels)
    if total_length > 255:
        raise NameTooLong
    for i, label in enumerate(labels):
        if len(label) > 63:
            raise LabelTooLong
        if not label and i != len(labels) - 1:
            raise EmptyLabel

def _maybe_convert_to_binary(label: Union[bytes, str]) -> bytes:
    """If label is ``str``, convert it to ``bytes``.  If it is already
    ``bytes`` just return it.

    """
    if isinstance(label, str):
        return label.encode('ascii')
    return label

@dns.immutable.immutable
class Name:
    """A DNS name.

    The dns.name.Name class represents a DNS name as a tuple of
    labels.  Each label is a ``bytes`` in DNS wire format.  Instances
    of the class are immutable.
    """
    __slots__ = ['labels']

    def __init__(self, labels: Iterable[Union[bytes, str]]):
        """*labels* is any iterable whose values are ``str`` or ``bytes``."""
        blabels = [_maybe_convert_to_binary(x) for x in labels]
        self.labels = tuple(blabels)
        _validate_labels(self.labels)

    def __copy__(self):
        return Name(self.labels)

    def __deepcopy__(self, memo):
        return Name(copy.deepcopy(self.labels, memo))

    def __getstate__(self):
        return {'labels': self.labels}

    def __setstate__(self, state):
        super().__setattr__('labels', state['labels'])
        _validate_labels(self.labels)

    def is_absolute(self) -> bool:
        """Is the most significant label of this name the root label?

        Returns a ``bool``.
        """
        return len(self.labels) > 0 and self.labels[-1] == b''

    def is_wild(self) -> bool:
        """Is this name wild?  (I.e. Is the least significant label '*'?)

        Returns a ``bool``.
        """
        return len(self.labels) > 0 and self.labels[0] == b'*'

    def __hash__(self) -> int:
        """Return a case-insensitive hash of the name.

        Returns an ``int``.
        """
        h = 0
        for label in self.labels:
            for c in label.lower():
                h += (h << 3) + c
        return h

        self           other          relation     order  nlabels

        =============  =============  ===========  =====  =======
        self           other          relation     order  nlabels
        =============  =============  ===========  =====  =======
        www.example.   www.example.   equal        0      3
        www.example.   example.       subdomain    > 0    2
        example.       www.example.   superdomain  < 0    2
        example1.com.  example2.com.  common anc.  < 0    2
        example1       example2.      none         < 0    0
        example1.      example2       none         > 0    0
        =============  =============  ===========  =====  =======
        """
        pass

    def is_subdomain(self, other: 'Name') -> bool:
        """Is self a subdomain of other?

        Note that the notion of subdomain includes equality, e.g.
        "dnspython.org" is a subdomain of itself.

        Returns a ``bool``.
        """
        pass

    def is_superdomain(self, other: 'Name') -> bool:
        """Is self a superdomain of other?

        Note that the notion of superdomain includes equality, e.g.
        "dnspython.org" is a superdomain of itself.

        Returns a ``bool``.
        """
        pass

    def canonicalize(self) -> 'Name':
        """Return a name which is equal to the current name, but is in
        DNSSEC canonical form.
        """
        pass

    def __eq__(self, other):
        if isinstance(other, Name):
            return self.fullcompare(other)[1] == 0
        else:
            return False

    def __ne__(self, other):
        if isinstance(other, Name):
            return self.fullcompare(other)[1] != 0
        else:
            return True

    def __lt__(self, other):
        if isinstance(other, Name):
            return self.fullcompare(other)[1] < 0
        else:
            return NotImplemented

    def __le__(self, other):
        if isinstance(other, Name):
            return self.fullcompare(other)[1] <= 0
        else:
            return NotImplemented

    def __ge__(self, other):
        if isinstance(other, Name):
            return self.fullcompare(other)[1] >= 0
        else:
            return NotImplemented

    def __gt__(self, other):
        if isinstance(other, Name):
            return self.fullcompare(other)[1] > 0
        else:
            return NotImplemented

    def __repr__(self):
        return '<DNS name ' + self.__str__() + '>'

    def __str__(self):
        return self.to_text(False)

    def to_text(self, omit_final_dot: bool=False) -> str:
        """Convert name to DNS text format.

        *omit_final_dot* is a ``bool``.  If True, don't emit the final
        dot (denoting the root label) for absolute names.  The default
        is False.

        Returns a ``str``.
        """
        pass

    def to_unicode(self, omit_final_dot: bool=False, idna_codec: Optional[IDNACodec]=None) -> str:
        """Convert name to Unicode text format.

        IDN ACE labels are converted to Unicode.

        *omit_final_dot* is a ``bool``.  If True, don't emit the final
        dot (denoting the root label) for absolute names.  The default
        is False.
        *idna_codec* specifies the IDNA encoder/decoder.  If None, the
        dns.name.IDNA_2003_Practical encoder/decoder is used.
        The IDNA_2003_Practical decoder does
        not impose any policy, it just decodes punycode, so if you
        don't want checking for compliance, you can use this decoder
        for IDNA2008 as well.

        Returns a ``str``.
        """
        pass

    def to_digestable(self, origin: Optional['Name']=None) -> bytes:
        """Convert name to a format suitable for digesting in hashes.

        The name is canonicalized and converted to uncompressed wire
        format.  All names in wire format are absolute.  If the name
        is a relative name, then an origin must be supplied.

        *origin* is a ``dns.name.Name`` or ``None``.  If the name is
        relative and origin is not ``None``, then origin will be appended
        to the name.

        Raises ``dns.name.NeedAbsoluteNameOrOrigin`` if the name is
        relative and no origin was provided.

        Returns a ``bytes``.
        """
        pass

    def to_wire(self, file: Optional[Any]=None, compress: Optional[CompressType]=None, origin: Optional['Name']=None, canonicalize: bool=False) -> Optional[bytes]:
        """Convert name to wire format, possibly compressing it.

        *file* is the file where the name is emitted (typically an
        io.BytesIO file).  If ``None`` (the default), a ``bytes``
        containing the wire name will be returned.

        *compress*, a ``dict``, is the compression table to use.  If
        ``None`` (the default), names will not be compressed.  Note that
        the compression code assumes that compression offset 0 is the
        start of *file*, and thus compression will not be correct
        if this is not the case.

        *origin* is a ``dns.name.Name`` or ``None``.  If the name is
        relative and origin is not ``None``, then *origin* will be appended
        to it.

        *canonicalize*, a ``bool``, indicates whether the name should
        be canonicalized; that is, converted to a format suitable for
        digesting in hashes.

        Raises ``dns.name.NeedAbsoluteNameOrOrigin`` if the name is
        relative and no origin was provided.

        Returns a ``bytes`` or ``None``.
        """
        pass

    def __len__(self) -> int:
        """The length of the name (in labels).

        Returns an ``int``.
        """
        return len(self.labels)

    def __getitem__(self, index):
        return self.labels[index]

    def __add__(self, other):
        return self.concatenate(other)

    def __sub__(self, other):
        return self.relativize(other)

    def split(self, depth: int) -> Tuple['Name', 'Name']:
        """Split a name into a prefix and suffix names at the specified depth.

        *depth* is an ``int`` specifying the number of labels in the suffix

        Raises ``ValueError`` if *depth* was not >= 0 and <= the length of the
        name.

        Returns the tuple ``(prefix, suffix)``.
        """
        pass

    def concatenate(self, other: 'Name') -> 'Name':
        """Return a new name which is the concatenation of self and other.

        Raises ``dns.name.AbsoluteConcatenation`` if the name is
        absolute and *other* is not the empty name.

        Returns a ``dns.name.Name``.
        """
        pass

    def relativize(self, origin: 'Name') -> 'Name':
        """If the name is a subdomain of *origin*, return a new name which is
        the name relative to origin.  Otherwise return the name.

        For example, relativizing ``www.dnspython.org.`` to origin
        ``dnspython.org.`` returns the name ``www``.  Relativizing ``example.``
        to origin ``dnspython.org.`` returns ``example.``.

        Returns a ``dns.name.Name``.
        """
        pass

    def derelativize(self, origin: 'Name') -> 'Name':
        """If the name is a relative name, return a new name which is the
        concatenation of the name and origin.  Otherwise return the name.

        For example, derelativizing ``www`` to origin ``dnspython.org.``
        returns the name ``www.dnspython.org.``.  Derelativizing ``example.``
        to origin ``dnspython.org.`` returns ``example.``.

        Returns a ``dns.name.Name``.
        """
        pass

    def choose_relativity(self, origin: Optional['Name']=None, relativize: bool=True) -> 'Name':
        """Return a name with the relativity desired by the caller.

        If *origin* is ``None``, then the name is returned.
        Otherwise, if *relativize* is ``True`` the name is
        relativized, and if *relativize* is ``False`` the name is
        derelativized.

        Returns a ``dns.name.Name``.
        """
        pass

    def parent(self) -> 'Name':
        """Return the parent of the name.

        For example, the parent of ``www.dnspython.org.`` is ``dnspython.org``.

        Raises ``dns.name.NoParent`` if the name is either the root name or the
        empty name, and thus has no parent.

        Returns a ``dns.name.Name``.
        """
        pass

    def predecessor(self, origin: 'Name', prefix_ok: bool=True) -> 'Name':
        """Return the maximal predecessor of *name* in the DNSSEC ordering in the zone
        whose origin is *origin*, or return the longest name under *origin* if the
        name is origin (i.e. wrap around to the longest name, which may still be
        *origin* due to length considerations.

        The relativity of the name is preserved, so if this name is relative
        then the method will return a relative name, and likewise if this name
        is absolute then the predecessor will be absolute.

        *prefix_ok* indicates if prefixing labels is allowed, and
        defaults to ``True``.  Normally it is good to allow this, but if computing
        a maximal predecessor at a zone cut point then ``False`` must be specified.
        """
        pass

    def successor(self, origin: 'Name', prefix_ok: bool=True) -> 'Name':
        """Return the minimal successor of *name* in the DNSSEC ordering in the zone
        whose origin is *origin*, or return *origin* if the successor cannot be
        computed due to name length limitations.

        Note that *origin* is returned in the "too long" cases because wrapping
        around to the origin is how NSEC records express "end of the zone".

        The relativity of the name is preserved, so if this name is relative
        then the method will return a relative name, and likewise if this name
        is absolute then the successor will be absolute.

        *prefix_ok* indicates if prefixing a new minimal label is allowed, and
        defaults to ``True``.  Normally it is good to allow this, but if computing
        a minimal successor at a zone cut point then ``False`` must be specified.
        """
        pass
root = Name([b''])
empty = Name([])

def from_unicode(text: str, origin: Optional[Name]=root, idna_codec: Optional[IDNACodec]=None) -> Name:
    """Convert unicode text into a Name object.

    Labels are encoded in IDN ACE form according to rules specified by
    the IDNA codec.

    *text*, a ``str``, is the text to convert into a name.

    *origin*, a ``dns.name.Name``, specifies the origin to
    append to non-absolute names.  The default is the root name.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    Returns a ``dns.name.Name``.
    """
    pass

def from_text(text: Union[bytes, str], origin: Optional[Name]=root, idna_codec: Optional[IDNACodec]=None) -> Name:
    """Convert text into a Name object.

    *text*, a ``bytes`` or ``str``, is the text to convert into a name.

    *origin*, a ``dns.name.Name``, specifies the origin to
    append to non-absolute names.  The default is the root name.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    Returns a ``dns.name.Name``.
    """
    pass

def from_wire_parser(parser: 'dns.wire.Parser') -> Name:
    """Convert possibly compressed wire format into a Name.

    *parser* is a dns.wire.Parser.

    Raises ``dns.name.BadPointer`` if a compression pointer did not
    point backwards in the message.

    Raises ``dns.name.BadLabelType`` if an invalid label type was encountered.

    Returns a ``dns.name.Name``
    """
    pass

def from_wire(message: bytes, current: int) -> Tuple[Name, int]:
    """Convert possibly compressed wire format into a Name.

    *message* is a ``bytes`` containing an entire DNS message in DNS
    wire form.

    *current*, an ``int``, is the offset of the beginning of the name
    from the start of the message

    Raises ``dns.name.BadPointer`` if a compression pointer did not
    point backwards in the message.

    Raises ``dns.name.BadLabelType`` if an invalid label type was encountered.

    Returns a ``(dns.name.Name, int)`` tuple consisting of the name
    that was read and the number of bytes of the wire format message
    which were consumed reading it.
    """
    pass
_MINIMAL_OCTET = b'\x00'
_MINIMAL_OCTET_VALUE = ord(_MINIMAL_OCTET)
_SUCCESSOR_PREFIX = Name([_MINIMAL_OCTET])
_MAXIMAL_OCTET = b'\xff'
_MAXIMAL_OCTET_VALUE = ord(_MAXIMAL_OCTET)
_AT_SIGN_VALUE = ord('@')
_LEFT_SQUARE_BRACKET_VALUE = ord('[')
