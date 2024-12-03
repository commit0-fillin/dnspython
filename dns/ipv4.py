"""IPv4 helper functions."""
from typing import Union
import dns.exception

def inet_ntoa(address: bytes) -> str:
    """Convert an IPv4 address in binary form to text form.

    *address*, a ``bytes``, the IPv4 address in binary form.

    Returns a ``str``.
    """
    if len(address) != 4:
        raise ValueError("IPv4 addresses are 4 bytes long")
    return '.'.join(str(byte) for byte in address)

def inet_aton(text: Union[str, bytes]) -> bytes:
    """Convert an IPv4 address in text form to binary form.

    *text*, a ``str`` or ``bytes``, the IPv4 address in textual form.

    Returns a ``bytes``.
    """
    if isinstance(text, bytes):
        text = text.decode()
    
    parts = text.split('.')
    if len(parts) != 4:
        raise dns.exception.SyntaxError("IPv4 address must have exactly 4 parts")
    
    try:
        bytes_parts = [int(part) for part in parts]
        if not all(0 <= byte <= 255 for byte in bytes_parts):
            raise ValueError
        return bytes(bytes_parts)
    except ValueError:
        raise dns.exception.SyntaxError("IPv4 address parts must be integers between 0 and 255")

def canonicalize(text: Union[str, bytes]) -> str:
    """Verify that *address* is a valid text form IPv4 address and return its
    canonical text form.

    *text*, a ``str`` or ``bytes``, the IPv4 address in textual form.

    Raises ``dns.exception.SyntaxError`` if the text is not valid.
    """
    try:
        binary = inet_aton(text)
        return inet_ntoa(binary)
    except ValueError as e:
        raise dns.exception.SyntaxError(str(e))
