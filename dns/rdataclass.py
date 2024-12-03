"""DNS Rdata Classes."""
import dns.enum
import dns.exception

class RdataClass(dns.enum.IntEnum):
    """DNS Rdata Class"""
    RESERVED0 = 0
    IN = 1
    INTERNET = IN
    CH = 3
    CHAOS = CH
    HS = 4
    HESIOD = HS
    NONE = 254
    ANY = 255
_metaclasses = {RdataClass.NONE, RdataClass.ANY}

class UnknownRdataclass(dns.exception.DNSException):
    """A DNS class is unknown."""

def from_text(text: str) -> RdataClass:
    """Convert text into a DNS rdata class value.

    The input text can be a defined DNS RR class mnemonic or
    instance of the DNS generic class syntax.

    For example, "IN" and "CLASS1" will both result in a value of 1.

    Raises ``dns.rdatatype.UnknownRdataclass`` if the class is unknown.

    Raises ``ValueError`` if the rdata class value is not >= 0 and <= 65535.

    Returns a ``dns.rdataclass.RdataClass``.
    """
    text = text.upper()
    try:
        return RdataClass[text]
    except KeyError:
        if text.startswith('CLASS'):
            try:
                value = int(text[5:])
                if 0 <= value <= 65535:
                    return RdataClass(value)
                else:
                    raise ValueError("Rdata class value must be between 0 and 65535")
            except ValueError:
                pass
        raise UnknownRdataclass(f"Unknown rdata class: {text}")

def to_text(value: RdataClass) -> str:
    """Convert a DNS rdata class value to text.

    If the value has a known mnemonic, it will be used, otherwise the
    DNS generic class syntax will be used.

    Raises ``ValueError`` if the rdata class value is not >= 0 and <= 65535.

    Returns a ``str``.
    """
    if not isinstance(value, int) or value < 0 or value > 65535:
        raise ValueError("Rdata class value must be between 0 and 65535")
    
    try:
        return RdataClass(value).name
    except ValueError:
        return f'CLASS{value}'

def is_metaclass(rdclass: RdataClass) -> bool:
    """True if the specified class is a metaclass.

    The currently defined metaclasses are ANY and NONE.

    *rdclass* is a ``dns.rdataclass.RdataClass``.
    """
    return rdclass in _metaclasses
RESERVED0 = RdataClass.RESERVED0
IN = RdataClass.IN
INTERNET = RdataClass.INTERNET
CH = RdataClass.CH
CHAOS = RdataClass.CHAOS
HS = RdataClass.HS
HESIOD = RdataClass.HESIOD
NONE = RdataClass.NONE
ANY = RdataClass.ANY
