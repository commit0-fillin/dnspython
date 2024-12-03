"""DNS Rdata Types."""
from typing import Dict
import dns.enum
import dns.exception

class RdataType(dns.enum.IntEnum):
    """DNS Rdata Type"""
    TYPE0 = 0
    NONE = 0
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAP_PTR = 23
    SIG = 24
    KEY = 25
    PX = 26
    GPOS = 27
    AAAA = 28
    LOC = 29
    NXT = 30
    SRV = 33
    NAPTR = 35
    KX = 36
    CERT = 37
    A6 = 38
    DNAME = 39
    OPT = 41
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    NINFO = 56
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    CSYNC = 62
    ZONEMD = 63
    SVCB = 64
    HTTPS = 65
    SPF = 99
    UNSPEC = 103
    NID = 104
    L32 = 105
    L64 = 106
    LP = 107
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    MAILB = 253
    MAILA = 254
    ANY = 255
    URI = 256
    CAA = 257
    AVC = 258
    AMTRELAY = 260
    TA = 32768
    DLV = 32769
_registered_by_text: Dict[str, RdataType] = {}
_registered_by_value: Dict[RdataType, str] = {}
_metatypes = {RdataType.OPT}
_singletons = {RdataType.SOA, RdataType.NXT, RdataType.DNAME, RdataType.NSEC, RdataType.CNAME}

class UnknownRdatatype(dns.exception.DNSException):
    """DNS resource record type is unknown."""

def from_text(text: str) -> RdataType:
    """Convert text into a DNS rdata type value.

    The input text can be a defined DNS RR type mnemonic or
    instance of the DNS generic type syntax.

    For example, "NS" and "TYPE2" will both result in a value of 2.

    Raises ``dns.rdatatype.UnknownRdatatype`` if the type is unknown.

    Raises ``ValueError`` if the rdata type value is not >= 0 and <= 65535.

    Returns a ``dns.rdatatype.RdataType``.
    """
    text = text.upper()
    try:
        return RdataType[text]
    except KeyError:
        if text.startswith('TYPE'):
            try:
                value = int(text[4:])
                if 0 <= value <= 65535:
                    return RdataType(value)
                else:
                    raise ValueError("Rdata type value must be between 0 and 65535")
            except ValueError:
                raise UnknownRdatatype(f"Unknown rdatatype {text}")
        else:
            raise UnknownRdatatype(f"Unknown rdatatype {text}")

def to_text(value: RdataType) -> str:
    """Convert a DNS rdata type value to text.

    If the value has a known mnemonic, it will be used, otherwise the
    DNS generic type syntax will be used.

    Raises ``ValueError`` if the rdata type value is not >= 0 and <= 65535.

    Returns a ``str``.
    """
    if not isinstance(value, int) or value < 0 or value > 65535:
        raise ValueError("Rdata type value must be between 0 and 65535")
    
    try:
        return RdataType(value).name
    except ValueError:
        return f'TYPE{value}'

def is_metatype(rdtype: RdataType) -> bool:
    """True if the specified type is a metatype.

    *rdtype* is a ``dns.rdatatype.RdataType``.

    The currently defined metatypes are TKEY, TSIG, IXFR, AXFR, MAILA,
    MAILB, ANY, and OPT.

    Returns a ``bool``.
    """
    return rdtype in _metatypes

def is_singleton(rdtype: RdataType) -> bool:
    """Is the specified type a singleton type?

    Singleton types can only have a single rdata in an rdataset, or a single
    RR in an RRset.

    The currently defined singleton types are CNAME, DNAME, NSEC, NXT, and
    SOA.

    *rdtype* is an ``int``.

    Returns a ``bool``.
    """
    return rdtype in _singletons

def register_type(rdtype: RdataType, rdtype_text: str, is_singleton: bool=False) -> None:
    """Dynamically register an rdatatype.

    *rdtype*, a ``dns.rdatatype.RdataType``, the rdatatype to register.

    *rdtype_text*, a ``str``, the textual form of the rdatatype.

    *is_singleton*, a ``bool``, indicating if the type is a singleton (i.e.
    RRsets of the type can have only one member.)
    """
    if not isinstance(rdtype, int) or rdtype < 0 or rdtype > 65535:
        raise ValueError("Rdata type value must be between 0 and 65535")
    
    if not isinstance(rdtype_text, str) or not rdtype_text:
        raise ValueError("Rdata type text must be a non-empty string")
    
    rdtype_text = rdtype_text.upper()
    
    if rdtype_text in _registered_by_text:
        raise ValueError(f"Rdata type text '{rdtype_text}' already registered")
    
    if rdtype in _registered_by_value:
        raise ValueError(f"Rdata type value {rdtype} already registered")
    
    _registered_by_text[rdtype_text] = RdataType(rdtype)
    _registered_by_value[RdataType(rdtype)] = rdtype_text
    
    if is_singleton:
        _singletons.add(RdataType(rdtype))
TYPE0 = RdataType.TYPE0
NONE = RdataType.NONE
A = RdataType.A
NS = RdataType.NS
MD = RdataType.MD
MF = RdataType.MF
CNAME = RdataType.CNAME
SOA = RdataType.SOA
MB = RdataType.MB
MG = RdataType.MG
MR = RdataType.MR
NULL = RdataType.NULL
WKS = RdataType.WKS
PTR = RdataType.PTR
HINFO = RdataType.HINFO
MINFO = RdataType.MINFO
MX = RdataType.MX
TXT = RdataType.TXT
RP = RdataType.RP
AFSDB = RdataType.AFSDB
X25 = RdataType.X25
ISDN = RdataType.ISDN
RT = RdataType.RT
NSAP = RdataType.NSAP
NSAP_PTR = RdataType.NSAP_PTR
SIG = RdataType.SIG
KEY = RdataType.KEY
PX = RdataType.PX
GPOS = RdataType.GPOS
AAAA = RdataType.AAAA
LOC = RdataType.LOC
NXT = RdataType.NXT
SRV = RdataType.SRV
NAPTR = RdataType.NAPTR
KX = RdataType.KX
CERT = RdataType.CERT
A6 = RdataType.A6
DNAME = RdataType.DNAME
OPT = RdataType.OPT
APL = RdataType.APL
DS = RdataType.DS
SSHFP = RdataType.SSHFP
IPSECKEY = RdataType.IPSECKEY
RRSIG = RdataType.RRSIG
NSEC = RdataType.NSEC
DNSKEY = RdataType.DNSKEY
DHCID = RdataType.DHCID
NSEC3 = RdataType.NSEC3
NSEC3PARAM = RdataType.NSEC3PARAM
TLSA = RdataType.TLSA
SMIMEA = RdataType.SMIMEA
HIP = RdataType.HIP
NINFO = RdataType.NINFO
CDS = RdataType.CDS
CDNSKEY = RdataType.CDNSKEY
OPENPGPKEY = RdataType.OPENPGPKEY
CSYNC = RdataType.CSYNC
ZONEMD = RdataType.ZONEMD
SVCB = RdataType.SVCB
HTTPS = RdataType.HTTPS
SPF = RdataType.SPF
UNSPEC = RdataType.UNSPEC
NID = RdataType.NID
L32 = RdataType.L32
L64 = RdataType.L64
LP = RdataType.LP
EUI48 = RdataType.EUI48
EUI64 = RdataType.EUI64
TKEY = RdataType.TKEY
TSIG = RdataType.TSIG
IXFR = RdataType.IXFR
AXFR = RdataType.AXFR
MAILB = RdataType.MAILB
MAILA = RdataType.MAILA
ANY = RdataType.ANY
URI = RdataType.URI
CAA = RdataType.CAA
AVC = RdataType.AVC
AMTRELAY = RdataType.AMTRELAY
TA = RdataType.TA
DLV = RdataType.DLV
