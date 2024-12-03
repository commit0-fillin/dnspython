"""DNS TTL conversion."""
from typing import Union
import dns.exception
MAX_TTL = 2 ** 32 - 1

class BadTTL(dns.exception.SyntaxError):
    """DNS TTL value is not well-formed."""

def from_text(text: str) -> int:
    """Convert the text form of a TTL to an integer.

    The BIND 8 units syntax for TTLs (e.g. '1w6d4h3m10s') is supported.

    *text*, a ``str``, the textual TTL.

    Raises ``dns.ttl.BadTTL`` if the TTL is not well-formed.

    Returns an ``int``.
    """
    if not text:
        raise BadTTL("TTL value cannot be empty")

    total_seconds = 0
    value = ""
    for char in text:
        if char.isdigit():
            value += char
        elif char.isalpha():
            if not value:
                raise BadTTL(f"Invalid TTL syntax: {text}")
            
            seconds = int(value)
            value = ""
            
            if char == 'w':
                total_seconds += seconds * 7 * 24 * 3600
            elif char == 'd':
                total_seconds += seconds * 24 * 3600
            elif char == 'h':
                total_seconds += seconds * 3600
            elif char == 'm':
                total_seconds += seconds * 60
            elif char == 's':
                total_seconds += seconds
            else:
                raise BadTTL(f"Invalid unit in TTL: {char}")
        else:
            raise BadTTL(f"Invalid character in TTL: {char}")

    if value:
        total_seconds += int(value)

    if total_seconds > MAX_TTL:
        raise BadTTL(f"TTL value {total_seconds} exceeds maximum allowed value of {MAX_TTL}")

    return total_seconds
