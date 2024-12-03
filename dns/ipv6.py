"""IPv6 helper functions."""
import binascii
import re
import itertools
from typing import List, Union
import dns.exception
import dns.ipv4
_leading_zero = re.compile('0+([0-9a-f]+)')

def inet_ntoa(address: bytes) -> str:
    """Convert an IPv6 address in binary form to text form.

    *address*, a ``bytes``, the IPv6 address in binary form.

    Raises ``ValueError`` if the address isn't 16 bytes long.
    Returns a ``str``.
    """
    if len(address) != 16:
        raise ValueError("IPv6 addresses are 16 bytes long")
    
    # Convert to hexadecimal representation
    hex_groups = [address[i:i+2].hex() for i in range(0, 16, 2)]
    
    # Find the longest run of consecutive zero groups
    longest_zero_run = max(
        (list(y) for (x, y) in itertools.groupby(hex_groups, lambda z: z == '0000') if x),
        key=len,
        default=[]
    )
    
    if len(longest_zero_run) > 1:
        zero_index = hex_groups.index('0000')
        hex_groups[zero_index:zero_index+len(longest_zero_run)] = ['']
        return ':'.join(group or ':' for group in hex_groups).replace(':::', '::').strip(':')
    else:
        return ':'.join(hex_groups)
_v4_ending = re.compile(b'(.*):(\\d+\\.\\d+\\.\\d+\\.\\d+)$')
_colon_colon_start = re.compile(b'::.*')
_colon_colon_end = re.compile(b'.*::$')

def inet_aton(text: Union[str, bytes], ignore_scope: bool=False) -> bytes:
    """Convert an IPv6 address in text form to binary form.

    *text*, a ``str`` or ``bytes``, the IPv6 address in textual form.

    *ignore_scope*, a ``bool``.  If ``True``, a scope will be ignored.
    If ``False``, the default, it is an error for a scope to be present.

    Returns a ``bytes``.
    """
    if isinstance(text, bytes):
        text = text.decode()
    
    if '%' in text:
        if ignore_scope:
            text = text.split('%')[0]
        else:
            raise dns.exception.SyntaxError("IPv6 address contains a scope")
    
    if '::' in text:
        left, right = text.split('::', 1)
        left_parts = left.split(':') if left else []
        right_parts = right.split(':') if right else []
        missing = 8 - (len(left_parts) + len(right_parts))
        parts = left_parts + ['0'] * missing + right_parts
    else:
        parts = text.split(':')
    
    if len(parts) != 8:
        raise dns.exception.SyntaxError("IPv6 address must have exactly 8 parts")
    
    try:
        return b''.join(int(part, 16).to_bytes(2, 'big') for part in parts)
    except ValueError:
        raise dns.exception.SyntaxError("Invalid hexadecimal in IPv6 address")
_mapped_prefix = b'\x00' * 10 + b'\xff\xff'

def is_mapped(address: bytes) -> bool:
    """Is the specified address a mapped IPv4 address?

    *address*, a ``bytes`` is an IPv6 address in binary form.

    Returns a ``bool``.
    """
    return len(address) == 16 and address.startswith(_mapped_prefix)

def canonicalize(text: Union[str, bytes]) -> str:
    """Verify that *address* is a valid text form IPv6 address and return its
    canonical text form.  Addresses with scopes are rejected.

    *text*, a ``str`` or ``bytes``, the IPv6 address in textual form.

    Raises ``dns.exception.SyntaxError`` if the text is not valid.
    """
    try:
        binary = inet_aton(text)
        return inet_ntoa(binary)
    except (ValueError, dns.exception.SyntaxError) as e:
        raise dns.exception.SyntaxError(f"Invalid IPv6 address: {str(e)}")
