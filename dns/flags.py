"""DNS Message Flags."""
import enum
from typing import Any

class Flag(enum.IntFlag):
    QR = 32768
    AA = 1024
    TC = 512
    RD = 256
    RA = 128
    AD = 32
    CD = 16

class EDNSFlag(enum.IntFlag):
    DO = 32768

def from_text(text: str) -> int:
    """Convert a space-separated list of flag text values into a flags
    value.

    Returns an ``int``
    """
    flags = 0
    for flag_text in text.split():
        try:
            flags |= Flag[flag_text.upper()]
        except KeyError:
            raise ValueError(f"Unknown flag: {flag_text}")
    return flags

def to_text(flags: int) -> str:
    """Convert a flags value into a space-separated list of flag text
    values.

    Returns a ``str``.
    """
    return ' '.join(flag.name for flag in Flag if flags & flag)

def edns_from_text(text: str) -> int:
    """Convert a space-separated list of EDNS flag text values into a EDNS
    flags value.

    Returns an ``int``
    """
    flags = 0
    for flag_text in text.split():
        try:
            flags |= EDNSFlag[flag_text.upper()]
        except KeyError:
            raise ValueError(f"Unknown EDNS flag: {flag_text}")
    return flags

def edns_to_text(flags: int) -> str:
    """Convert an EDNS flags value into a space-separated list of EDNS flag
    text values.

    Returns a ``str``.
    """
    return ' '.join(flag.name for flag in EDNSFlag if flags & flag)
QR = Flag.QR
AA = Flag.AA
TC = Flag.TC
RD = Flag.RD
RA = Flag.RA
AD = Flag.AD
CD = Flag.CD
DO = EDNSFlag.DO
