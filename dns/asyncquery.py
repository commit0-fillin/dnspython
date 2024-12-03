"""Talk to a DNS server."""
import base64
import contextlib
import socket
import struct
import time
from typing import Any, Dict, Optional, Tuple, Union
import dns.asyncbackend
import dns.exception
import dns.inet
import dns.message
import dns.name
import dns.quic
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.transaction
from dns._asyncbackend import NullContext
from dns.query import BadResponse, NoDOH, NoDOQ, UDPMode, _compute_times, _make_dot_ssl_context, _matches_destination, _remaining, have_doh, ssl
if have_doh:
    import httpx
_lltuple = dns.inet.low_level_address_tuple

async def send_udp(sock: dns.asyncbackend.DatagramSocket, what: Union[dns.message.Message, bytes], destination: Any, expiration: Optional[float]=None) -> Tuple[int, float]:
    """Send a DNS message to the specified UDP socket.

    *sock*, a ``dns.asyncbackend.DatagramSocket``.

    *what*, a ``bytes`` or ``dns.message.Message``, the message to send.

    *destination*, a destination tuple appropriate for the address family
    of the socket, specifying where to send the query.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.  The expiration value is meaningless for the asyncio backend, as
    asyncio's transport sendto() never blocks.

    Returns an ``(int, float)`` tuple of bytes sent and the sent time.
    """
    if isinstance(what, dns.message.Message):
        what = what.to_wire()
    sent_time = time.time()
    n = await sock.sendto(what, destination)
    return (n, sent_time)

async def receive_udp(sock: dns.asyncbackend.DatagramSocket, destination: Optional[Any]=None, expiration: Optional[float]=None, ignore_unexpected: bool=False, one_rr_per_rrset: bool=False, keyring: Optional[Dict[dns.name.Name, dns.tsig.Key]]=None, request_mac: Optional[bytes]=b'', ignore_trailing: bool=False, raise_on_truncation: bool=False, ignore_errors: bool=False, query: Optional[dns.message.Message]=None) -> Any:
    """Read a DNS message from a UDP socket.

    *sock*, a ``dns.asyncbackend.DatagramSocket``.

    See :py:func:`dns.query.receive_udp()` for the documentation of the other
    parameters, and exceptions.

    Returns a ``(dns.message.Message, float, tuple)`` tuple of the received message, the
    received time, and the address where the message arrived from.
    """
    wire, from_address = await sock.recvfrom(65535)
    received_time = time.time()
    r = dns.message.from_wire(wire, keyring=keyring, request_mac=request_mac,
                              one_rr_per_rrset=one_rr_per_rrset,
                              ignore_trailing=ignore_trailing,
                              raise_on_truncation=raise_on_truncation,
                              ignore_errors=ignore_errors)
    if destination:
        if not _matches_destination(from_address, destination, sock.family):
            if ignore_unexpected:
                return await receive_udp(sock, destination, expiration,
                                         ignore_unexpected, one_rr_per_rrset,
                                         keyring, request_mac, ignore_trailing,
                                         raise_on_truncation, ignore_errors, query)
            raise dns.exception.FormError("got a response from the wrong server")
    return (r, received_time, from_address)

async def udp(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=53, source: Optional[str]=None, source_port: int=0, ignore_unexpected: bool=False, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, raise_on_truncation: bool=False, sock: Optional[dns.asyncbackend.DatagramSocket]=None, backend: Optional[dns.asyncbackend.Backend]=None, ignore_errors: bool=False) -> dns.message.Message:
    """Return the response obtained after sending a query via UDP.

    *sock*, a ``dns.asyncbackend.DatagramSocket``, or ``None``,
    the socket to use for the query.  If ``None``, the default, a
    socket is created.  Note that if a socket is provided, the
    *source*, *source_port*, and *backend* are ignored.

    *backend*, a ``dns.asyncbackend.Backend``, or ``None``.  If ``None``,
    the default, then dnspython will use the default backend.

    See :py:func:`dns.query.udp()` for the documentation of the other
    parameters, exceptions, and return type of this method.
    """
    wire = q.to_wire()
    (begin_time, expiration) = _compute_times(timeout)
    s = None
    if sock:
        s = sock
    else:
        if backend is None:
            backend = dns.asyncbackend.get_default_backend()
        af = dns.inet.af_for_address(where)
        destination = _lltuple((where, port), af)
        s = await backend.make_socket(af, socket.SOCK_DGRAM, 0, source, source_port)
    try:
        await send_udp(s, wire, destination, expiration)
        (r, received_time, _) = await receive_udp(s, destination, expiration,
                                                  ignore_unexpected,
                                                  one_rr_per_rrset,
                                                  q.keyring, q.mac,
                                                  ignore_trailing,
                                                  raise_on_truncation,
                                                  ignore_errors,
                                                  q)
        r.time = received_time - begin_time
        if not q.is_response(r):
            raise BadResponse
        return r
    finally:
        if not sock:
            await s.close()

async def udp_with_fallback(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=53, source: Optional[str]=None, source_port: int=0, ignore_unexpected: bool=False, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, udp_sock: Optional[dns.asyncbackend.DatagramSocket]=None, tcp_sock: Optional[dns.asyncbackend.StreamSocket]=None, backend: Optional[dns.asyncbackend.Backend]=None, ignore_errors: bool=False) -> Tuple[dns.message.Message, bool]:
    """Return the response to the query, trying UDP first and falling back
    to TCP if UDP results in a truncated response.

    *udp_sock*, a ``dns.asyncbackend.DatagramSocket``, or ``None``,
    the socket to use for the UDP query.  If ``None``, the default, a
    socket is created.  Note that if a socket is provided the *source*,
    *source_port*, and *backend* are ignored for the UDP query.

    *tcp_sock*, a ``dns.asyncbackend.StreamSocket``, or ``None``, the
    socket to use for the TCP query.  If ``None``, the default, a
    socket is created.  Note that if a socket is provided *where*,
    *source*, *source_port*, and *backend*  are ignored for the TCP query.

    *backend*, a ``dns.asyncbackend.Backend``, or ``None``.  If ``None``,
    the default, then dnspython will use the default backend.

    See :py:func:`dns.query.udp_with_fallback()` for the documentation
    of the other parameters, exceptions, and return type of this
    method.
    """
    pass

async def send_tcp(sock: dns.asyncbackend.StreamSocket, what: Union[dns.message.Message, bytes], expiration: Optional[float]=None) -> Tuple[int, float]:
    """Send a DNS message to the specified TCP socket.

    *sock*, a ``dns.asyncbackend.StreamSocket``.

    See :py:func:`dns.query.send_tcp()` for the documentation of the other
    parameters, exceptions, and return type of this method.
    """
    pass

async def _read_exactly(sock, count, expiration):
    """Read the specified number of bytes from stream.  Keep trying until we
    either get the desired amount, or we hit EOF.
    """
    pass

async def receive_tcp(sock: dns.asyncbackend.StreamSocket, expiration: Optional[float]=None, one_rr_per_rrset: bool=False, keyring: Optional[Dict[dns.name.Name, dns.tsig.Key]]=None, request_mac: Optional[bytes]=b'', ignore_trailing: bool=False) -> Tuple[dns.message.Message, float]:
    """Read a DNS message from a TCP socket.

    *sock*, a ``dns.asyncbackend.StreamSocket``.

    See :py:func:`dns.query.receive_tcp()` for the documentation of the other
    parameters, exceptions, and return type of this method.
    """
    pass

async def tcp(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=53, source: Optional[str]=None, source_port: int=0, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, sock: Optional[dns.asyncbackend.StreamSocket]=None, backend: Optional[dns.asyncbackend.Backend]=None) -> dns.message.Message:
    """Return the response obtained after sending a query via TCP.

    *sock*, a ``dns.asyncbacket.StreamSocket``, or ``None``, the
    socket to use for the query.  If ``None``, the default, a socket
    is created.  Note that if a socket is provided
    *where*, *port*, *source*, *source_port*, and *backend* are ignored.

    *backend*, a ``dns.asyncbackend.Backend``, or ``None``.  If ``None``,
    the default, then dnspython will use the default backend.

    See :py:func:`dns.query.tcp()` for the documentation of the other
    parameters, exceptions, and return type of this method.
    """
    pass

async def tls(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=853, source: Optional[str]=None, source_port: int=0, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, sock: Optional[dns.asyncbackend.StreamSocket]=None, backend: Optional[dns.asyncbackend.Backend]=None, ssl_context: Optional[ssl.SSLContext]=None, server_hostname: Optional[str]=None, verify: Union[bool, str]=True) -> dns.message.Message:
    """Return the response obtained after sending a query via TLS.

    *sock*, an ``asyncbackend.StreamSocket``, or ``None``, the socket
    to use for the query.  If ``None``, the default, a socket is
    created.  Note that if a socket is provided, it must be a
    connected SSL stream socket, and *where*, *port*,
    *source*, *source_port*, *backend*, *ssl_context*, and *server_hostname*
    are ignored.

    *backend*, a ``dns.asyncbackend.Backend``, or ``None``.  If ``None``,
    the default, then dnspython will use the default backend.

    See :py:func:`dns.query.tls()` for the documentation of the other
    parameters, exceptions, and return type of this method.
    """
    pass

async def https(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=443, source: Optional[str]=None, source_port: int=0, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, client: Optional['httpx.AsyncClient']=None, path: str='/dns-query', post: bool=True, verify: Union[bool, str]=True, bootstrap_address: Optional[str]=None, resolver: Optional['dns.asyncresolver.Resolver']=None, family: Optional[int]=socket.AF_UNSPEC) -> dns.message.Message:
    """Return the response obtained after sending a query via DNS-over-HTTPS.

    *client*, a ``httpx.AsyncClient``.  If provided, the client to use for
    the query.

    Unlike the other dnspython async functions, a backend cannot be provided
    in this function because httpx always auto-detects the async backend.

    See :py:func:`dns.query.https()` for the documentation of the other
    parameters, exceptions, and return type of this method.
    """
    pass

async def inbound_xfr(where: str, txn_manager: dns.transaction.TransactionManager, query: Optional[dns.message.Message]=None, port: int=53, timeout: Optional[float]=None, lifetime: Optional[float]=None, source: Optional[str]=None, source_port: int=0, udp_mode: UDPMode=UDPMode.NEVER, backend: Optional[dns.asyncbackend.Backend]=None) -> None:
    """Conduct an inbound transfer and apply it via a transaction from the
    txn_manager.

    *backend*, a ``dns.asyncbackend.Backend``, or ``None``.  If ``None``,
    the default, then dnspython will use the default backend.

    See :py:func:`dns.query.inbound_xfr()` for the documentation of
    the other parameters, exceptions, and return type of this method.
    """
    pass

async def quic(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=853, source: Optional[str]=None, source_port: int=0, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, connection: Optional[dns.quic.AsyncQuicConnection]=None, verify: Union[bool, str]=True, backend: Optional[dns.asyncbackend.Backend]=None, server_hostname: Optional[str]=None) -> dns.message.Message:
    """Return the response obtained after sending an asynchronous query via
    DNS-over-QUIC.

    *backend*, a ``dns.asyncbackend.Backend``, or ``None``.  If ``None``,
    the default, then dnspython will use the default backend.

    See :py:func:`dns.query.quic()` for the documentation of the other
    parameters, exceptions, and return type of this method.
    """
    pass
