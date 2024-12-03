"""Generic Internet address helper functions."""
import socket
from typing import Any, Optional, Tuple
import dns.ipv4
import dns.ipv6
AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6

def inet_pton(family: int, text: str) -> bytes:
    """Convert the textual form of a network address into its binary form.

    *family* is an ``int``, the address family.

    *text* is a ``str``, the textual address.

    Raises ``NotImplementedError`` if the address family specified is not
    implemented.

    Returns a ``bytes``.
    """
    if family == AF_INET:
        return dns.ipv4.inet_aton(text)
    elif family == AF_INET6:
        return dns.ipv6.inet_aton(text)
    else:
        raise NotImplementedError(f"Address family {family} not supported")

def inet_ntop(family: int, address: bytes) -> str:
    """Convert the binary form of a network address into its textual form.

    *family* is an ``int``, the address family.

    *address* is a ``bytes``, the network address in binary form.

    Raises ``NotImplementedError`` if the address family specified is not
    implemented.

    Returns a ``str``.
    """
    if family == AF_INET:
        return dns.ipv4.inet_ntoa(address)
    elif family == AF_INET6:
        return dns.ipv6.inet_ntoa(address)
    else:
        raise NotImplementedError(f"Address family {family} not supported")

def af_for_address(text: str) -> int:
    """Determine the address family of a textual-form network address.

    *text*, a ``str``, the textual address.

    Raises ``ValueError`` if the address family cannot be determined
    from the input.

    Returns an ``int``.
    """
    try:
        dns.ipv4.inet_aton(text)
        return AF_INET
    except dns.exception.SyntaxError:
        try:
            dns.ipv6.inet_aton(text)
            return AF_INET6
        except dns.exception.SyntaxError:
            raise ValueError(f"Invalid IP address: {text}")

def is_multicast(text: str) -> bool:
    """Is the textual-form network address a multicast address?

    *text*, a ``str``, the textual address.

    Raises ``ValueError`` if the address family cannot be determined
    from the input.

    Returns a ``bool``.
    """
    family = af_for_address(text)
    if family == AF_INET:
        first_byte = int(text.split('.')[0])
        return 224 <= first_byte <= 239
    elif family == AF_INET6:
        return text.startswith('ff')
    else:
        raise ValueError(f"Unsupported address family for {text}")

def is_address(text: str) -> bool:
    """Is the specified string an IPv4 or IPv6 address?

    *text*, a ``str``, the textual address.

    Returns a ``bool``.
    """
    try:
        af_for_address(text)
        return True
    except ValueError:
        return False

def low_level_address_tuple(high_tuple: Tuple[str, int], af: Optional[int]=None) -> Any:
    """Given a "high-level" address tuple, i.e.
    an (address, port) return the appropriate "low-level" address tuple
    suitable for use in socket calls.

    If an *af* other than ``None`` is provided, it is assumed the
    address in the high-level tuple is valid and has that af.  If af
    is ``None``, then af_for_address will be called.
    """
    address, port = high_tuple
    if af is None:
        af = af_for_address(address)
    
    if af == AF_INET:
        return (address, port)
    elif af == AF_INET6:
        return (address, port, 0, 0)
    else:
        raise ValueError(f"Unsupported address family: {af}")

def any_for_af(af):
    """Return the 'any' address for the specified address family."""
    if af == AF_INET:
        return '0.0.0.0'
    elif af == AF_INET6:
        return '::'
    else:
        raise ValueError(f"Unsupported address family: {af}")

def canonicalize(text: str) -> str:
    """Verify that *address* is a valid text form IPv4 or IPv6 address and return its
    canonical text form.  IPv6 addresses with scopes are rejected.

    *text*, a ``str``, the address in textual form.

    Raises ``ValueError`` if the text is not valid.
    """
    try:
        af = af_for_address(text)
        if af == AF_INET:
            return dns.ipv4.canonicalize(text)
        elif af == AF_INET6:
            return dns.ipv6.canonicalize(text)
    except dns.exception.SyntaxError as e:
        raise ValueError(str(e))
