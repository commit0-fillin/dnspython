"""Talk to a DNS server."""
import base64
import contextlib
import enum
import errno
import os
import os.path
import selectors
import socket
import struct
import time
from typing import Any, Dict, Optional, Tuple, Union
import dns._features
import dns.exception
import dns.inet
import dns.message
import dns.name
import dns.quic
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.serial
import dns.transaction
import dns.tsig
import dns.xfr
_have_httpx = dns._features.have('doh')
if _have_httpx:
    import httpcore._backends.sync
    import httpx
    _CoreNetworkBackend = httpcore.NetworkBackend
    _CoreSyncStream = httpcore._backends.sync.SyncStream

    class _NetworkBackend(_CoreNetworkBackend):

        def __init__(self, resolver, local_port, bootstrap_address, family):
            super().__init__()
            self._local_port = local_port
            self._resolver = resolver
            self._bootstrap_address = bootstrap_address
            self._family = family
            self._socket_kwargs = {
                'local_port': local_port,
                'family': family
            }

    class _HTTPTransport(httpx.HTTPTransport):

        def __init__(self, *args, local_port=0, bootstrap_address=None, resolver=None, family=socket.AF_UNSPEC, **kwargs):
            if resolver is None:
                import dns.resolver
                resolver = dns.resolver.Resolver()
            super().__init__(*args, **kwargs)
            self._pool._network_backend = _NetworkBackend(resolver, local_port, bootstrap_address, family)
else:

    class _HTTPTransport:
        pass
have_doh = _have_httpx
try:
    import ssl
except ImportError:

    class ssl:
        CERT_NONE = 0

        class WantReadException(Exception):
            pass

        class WantWriteException(Exception):
            pass

        class SSLContext:
            pass

        class SSLSocket:
            pass
socket_factory = socket.socket

class UnexpectedSource(dns.exception.DNSException):
    """A DNS query response came from an unexpected address or port."""

class BadResponse(dns.exception.FormError):
    """A DNS query response does not respond to the question asked."""

class NoDOH(dns.exception.DNSException):
    """DNS over HTTPS (DOH) was requested but the httpx module is not
    available."""

class NoDOQ(dns.exception.DNSException):
    """DNS over QUIC (DOQ) was requested but the aioquic module is not
    available."""
TransferError = dns.xfr.TransferError
if hasattr(selectors, 'PollSelector'):
    _selector_class = selectors.PollSelector
else:
    _selector_class = selectors.SelectSelector

def https(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=443, source: Optional[str]=None, source_port: int=0, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, session: Optional[Any]=None, path: str='/dns-query', post: bool=True, bootstrap_address: Optional[str]=None, verify: Union[bool, str]=True, resolver: Optional['dns.resolver.Resolver']=None, family: Optional[int]=socket.AF_UNSPEC) -> dns.message.Message:
    """Return the response obtained after sending a query via DNS-over-HTTPS.

    *q*, a ``dns.message.Message``, the query to send.

    *where*, a ``str``, the nameserver IP address or the full URL. If an IP address is
    given, the URL will be constructed using the following schema:
    https://<IP-address>:<port>/<path>.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the query
    times out. If ``None``, the default, wait forever.

    *port*, a ``int``, the port to send the query to. The default is 443.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying the source
    address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message. The default is
    0.

    *one_rr_per_rrset*, a ``bool``. If ``True``, put each RR into its own RRset.

    *ignore_trailing*, a ``bool``. If ``True``, ignore trailing junk at end of the
    received message.

    *session*, an ``httpx.Client``.  If provided, the client session to use to send the
    queries.

    *path*, a ``str``. If *where* is an IP address, then *path* will be used to
    construct the URL to send the DNS query to.

    *post*, a ``bool``. If ``True``, the default, POST method will be used.

    *bootstrap_address*, a ``str``, the IP address to use to bypass resolution.

    *verify*, a ``bool`` or ``str``.  If a ``True``, then TLS certificate verification
    of the server is done using the default CA bundle; if ``False``, then no
    verification is done; if a `str` then it specifies the path to a certificate file or
    directory which will be used for verification.

    *resolver*, a ``dns.resolver.Resolver`` or ``None``, the resolver to use for
    resolution of hostnames in URLs.  If not specified, a new resolver with a default
    configuration will be used; note this is *not* the default resolver as that resolver
    might have been configured to use DoH causing a chicken-and-egg problem.  This
    parameter only has an effect if the HTTP library is httpx.

    *family*, an ``int``, the address family.  If socket.AF_UNSPEC (the default), both A
    and AAAA records will be retrieved.

    Returns a ``dns.message.Message``.
    """
    if not _have_httpx:
        raise NoDOH("DNS over HTTPS (DOH) requires the httpx module")

    wire = q.to_wire()
    try:
        if session is None:
            transport = _HTTPTransport(local_port=source_port, bootstrap_address=bootstrap_address,
                                       resolver=resolver, family=family)
            session = httpx.Client(transport=transport, verify=verify)
            close_session = True
        else:
            close_session = False

        if dns.inet.is_address(where):
            url = f'https://{where}:{port}{path}'
        else:
            url = where

        headers = {
            'accept': 'application/dns-message',
            'content-type': 'application/dns-message',
        }

        if post:
            response = session.post(url, content=wire, headers=headers, timeout=timeout)
        else:
            response = session.get(url, params={'dns': base64.urlsafe_b64encode(wire).rstrip(b'=')},
                                   headers=headers, timeout=timeout)

        response.raise_for_status()

        r = dns.message.from_wire(response.content,
                                  keyring=q.keyring,
                                  request_mac=q.request_mac,
                                  one_rr_per_rrset=one_rr_per_rrset,
                                  ignore_trailing=ignore_trailing)
        r.time = response.elapsed.total_seconds()
        if not q.is_response(r):
            raise BadResponse
        return r
    finally:
        if close_session:
            session.close()

def _udp_recv(sock, max_size, expiration):
    """Reads a datagram from the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    while True:
        try:
            return sock.recvfrom(max_size)
        except socket.timeout:
            if expiration is not None and time.time() >= expiration:
                raise dns.exception.Timeout
        except BlockingIOError:
            if expiration is not None and time.time() >= expiration:
                raise dns.exception.Timeout

def _udp_send(sock, data, destination, expiration):
    """Sends the specified datagram to destination over the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    while True:
        try:
            return sock.sendto(data, destination)
        except socket.timeout:
            if expiration is not None and time.time() >= expiration:
                raise dns.exception.Timeout
        except BlockingIOError:
            if expiration is not None and time.time() >= expiration:
                raise dns.exception.Timeout

def send_udp(sock: Any, what: Union[dns.message.Message, bytes], destination: Any, expiration: Optional[float]=None) -> Tuple[int, float]:
    """Send a DNS message to the specified UDP socket.

    *sock*, a ``socket``.

    *what*, a ``bytes`` or ``dns.message.Message``, the message to send.

    *destination*, a destination tuple appropriate for the address family
    of the socket, specifying where to send the query.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.

    Returns an ``(int, float)`` tuple of bytes sent and the sent time.
    """
    if isinstance(what, dns.message.Message):
        what = what.to_wire()
    sent_time = time.time()
    n = _udp_send(sock, what, destination, expiration)
    return (n, sent_time)

def receive_udp(sock: Any, destination: Optional[Any]=None, expiration: Optional[float]=None, ignore_unexpected: bool=False, one_rr_per_rrset: bool=False, keyring: Optional[Dict[dns.name.Name, dns.tsig.Key]]=None, request_mac: Optional[bytes]=b'', ignore_trailing: bool=False, raise_on_truncation: bool=False, ignore_errors: bool=False, query: Optional[dns.message.Message]=None) -> Any:
    """Read a DNS message from a UDP socket.

    *sock*, a ``socket``.

    *destination*, a destination tuple appropriate for the address family
    of the socket, specifying where the message is expected to arrive from.
    When receiving a response, this would be where the associated query was
    sent.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.

    *ignore_unexpected*, a ``bool``.  If ``True``, ignore responses from
    unexpected sources.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *keyring*, a ``dict``, the keyring to use for TSIG.

    *request_mac*, a ``bytes`` or ``None``, the MAC of the request (for TSIG).

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    *raise_on_truncation*, a ``bool``.  If ``True``, raise an exception if
    the TC bit is set.

    Raises if the message is malformed, if network errors occur, of if
    there is a timeout.

    If *destination* is not ``None``, returns a ``(dns.message.Message, float)``
    tuple of the received message and the received time.

    If *destination* is ``None``, returns a
    ``(dns.message.Message, float, tuple)``
    tuple of the received message, the received time, and the address where
    the message arrived from.

    *ignore_errors*, a ``bool``.  If various format errors or response
    mismatches occur, ignore them and keep listening for a valid response.
    The default is ``False``.

    *query*, a ``dns.message.Message`` or ``None``.  If not ``None`` and
    *ignore_errors* is ``True``, check that the received message is a response
    to this query, and if not keep listening for a valid response.
    """
    pass

def udp(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=53, source: Optional[str]=None, source_port: int=0, ignore_unexpected: bool=False, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, raise_on_truncation: bool=False, sock: Optional[Any]=None, ignore_errors: bool=False) -> dns.message.Message:
    """Return the response obtained after sending a query via UDP.

    *q*, a ``dns.message.Message``, the query to send

    *where*, a ``str`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the
    query times out.  If ``None``, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *ignore_unexpected*, a ``bool``.  If ``True``, ignore responses from
    unexpected sources.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    *raise_on_truncation*, a ``bool``.  If ``True``, raise an exception if
    the TC bit is set.

    *sock*, a ``socket.socket``, or ``None``, the socket to use for the
    query.  If ``None``, the default, a socket is created.  Note that
    if a socket is provided, it must be a nonblocking datagram socket,
    and the *source* and *source_port* are ignored.

    *ignore_errors*, a ``bool``.  If various format errors or response
    mismatches occur, ignore them and keep listening for a valid response.
    The default is ``False``.

    Returns a ``dns.message.Message``.
    """
    pass

def udp_with_fallback(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=53, source: Optional[str]=None, source_port: int=0, ignore_unexpected: bool=False, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, udp_sock: Optional[Any]=None, tcp_sock: Optional[Any]=None, ignore_errors: bool=False) -> Tuple[dns.message.Message, bool]:
    """Return the response to the query, trying UDP first and falling back
    to TCP if UDP results in a truncated response.

    *q*, a ``dns.message.Message``, the query to send

    *where*, a ``str`` containing an IPv4 or IPv6 address,  where to send the message.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the query
    times out.  If ``None``, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying the source
    address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message. The default is
    0.

    *ignore_unexpected*, a ``bool``.  If ``True``, ignore responses from unexpected
    sources.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing junk at end of the
    received message.

    *udp_sock*, a ``socket.socket``, or ``None``, the socket to use for the UDP query.
    If ``None``, the default, a socket is created.  Note that if a socket is provided,
    it must be a nonblocking datagram socket, and the *source* and *source_port* are
    ignored for the UDP query.

    *tcp_sock*, a ``socket.socket``, or ``None``, the connected socket to use for the
    TCP query.  If ``None``, the default, a socket is created.  Note that if a socket is
    provided, it must be a nonblocking connected stream socket, and *where*, *source*
    and *source_port* are ignored for the TCP query.

    *ignore_errors*, a ``bool``.  If various format errors or response mismatches occur
    while listening for UDP, ignore them and keep listening for a valid response. The
    default is ``False``.

    Returns a (``dns.message.Message``, tcp) tuple where tcp is ``True`` if and only if
    TCP was used.
    """
    pass

def _net_read(sock, count, expiration):
    """Read the specified number of bytes from sock.  Keep trying until we
    either get the desired amount, or we hit EOF.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    pass

def _net_write(sock, data, expiration):
    """Write the specified data to the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    pass

def send_tcp(sock: Any, what: Union[dns.message.Message, bytes], expiration: Optional[float]=None) -> Tuple[int, float]:
    """Send a DNS message to the specified TCP socket.

    *sock*, a ``socket``.

    *what*, a ``bytes`` or ``dns.message.Message``, the message to send.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.

    Returns an ``(int, float)`` tuple of bytes sent and the sent time.
    """
    pass

def receive_tcp(sock: Any, expiration: Optional[float]=None, one_rr_per_rrset: bool=False, keyring: Optional[Dict[dns.name.Name, dns.tsig.Key]]=None, request_mac: Optional[bytes]=b'', ignore_trailing: bool=False) -> Tuple[dns.message.Message, float]:
    """Read a DNS message from a TCP socket.

    *sock*, a ``socket``.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *keyring*, a ``dict``, the keyring to use for TSIG.

    *request_mac*, a ``bytes`` or ``None``, the MAC of the request (for TSIG).

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    Raises if the message is malformed, if network errors occur, of if
    there is a timeout.

    Returns a ``(dns.message.Message, float)`` tuple of the received message
    and the received time.
    """
    pass

def tcp(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=53, source: Optional[str]=None, source_port: int=0, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, sock: Optional[Any]=None) -> dns.message.Message:
    """Return the response obtained after sending a query via TCP.

    *q*, a ``dns.message.Message``, the query to send

    *where*, a ``str`` containing an IPv4 or IPv6 address, where
    to send the message.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the
    query times out.  If ``None``, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    *sock*, a ``socket.socket``, or ``None``, the connected socket to use for the
    query.  If ``None``, the default, a socket is created.  Note that
    if a socket is provided, it must be a nonblocking connected stream
    socket, and *where*, *port*, *source* and *source_port* are ignored.

    Returns a ``dns.message.Message``.
    """
    pass

def tls(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=853, source: Optional[str]=None, source_port: int=0, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, sock: Optional[ssl.SSLSocket]=None, ssl_context: Optional[ssl.SSLContext]=None, server_hostname: Optional[str]=None, verify: Union[bool, str]=True) -> dns.message.Message:
    """Return the response obtained after sending a query via TLS.

    *q*, a ``dns.message.Message``, the query to send

    *where*, a ``str`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the
    query times out.  If ``None``, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 853.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    *sock*, an ``ssl.SSLSocket``, or ``None``, the socket to use for
    the query.  If ``None``, the default, a socket is created.  Note
    that if a socket is provided, it must be a nonblocking connected
    SSL stream socket, and *where*, *port*, *source*, *source_port*,
    and *ssl_context* are ignored.

    *ssl_context*, an ``ssl.SSLContext``, the context to use when establishing
    a TLS connection. If ``None``, the default, creates one with the default
    configuration.

    *server_hostname*, a ``str`` containing the server's hostname.  The
    default is ``None``, which means that no hostname is known, and if an
    SSL context is created, hostname checking will be disabled.

    *verify*, a ``bool`` or ``str``.  If a ``True``, then TLS certificate verification
    of the server is done using the default CA bundle; if ``False``, then no
    verification is done; if a `str` then it specifies the path to a certificate file or
    directory which will be used for verification.

    Returns a ``dns.message.Message``.

    """
    pass

def quic(q: dns.message.Message, where: str, timeout: Optional[float]=None, port: int=853, source: Optional[str]=None, source_port: int=0, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, connection: Optional[dns.quic.SyncQuicConnection]=None, verify: Union[bool, str]=True, server_hostname: Optional[str]=None) -> dns.message.Message:
    """Return the response obtained after sending a query via DNS-over-QUIC.

    *q*, a ``dns.message.Message``, the query to send.

    *where*, a ``str``, the nameserver IP address.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the query
    times out. If ``None``, the default, wait forever.

    *port*, a ``int``, the port to send the query to. The default is 853.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying the source
    address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message. The default is
    0.

    *one_rr_per_rrset*, a ``bool``. If ``True``, put each RR into its own RRset.

    *ignore_trailing*, a ``bool``. If ``True``, ignore trailing junk at end of the
    received message.

    *connection*, a ``dns.quic.SyncQuicConnection``.  If provided, the
    connection to use to send the query.

    *verify*, a ``bool`` or ``str``.  If a ``True``, then TLS certificate verification
    of the server is done using the default CA bundle; if ``False``, then no
    verification is done; if a `str` then it specifies the path to a certificate file or
    directory which will be used for verification.

    *server_hostname*, a ``str`` containing the server's hostname.  The
    default is ``None``, which means that no hostname is known, and if an
    SSL context is created, hostname checking will be disabled.

    Returns a ``dns.message.Message``.
    """
    pass

def xfr(where: str, zone: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.AXFR, rdclass: Union[dns.rdataclass.RdataClass, str]=dns.rdataclass.IN, timeout: Optional[float]=None, port: int=53, keyring: Optional[Dict[dns.name.Name, dns.tsig.Key]]=None, keyname: Optional[Union[dns.name.Name, str]]=None, relativize: bool=True, lifetime: Optional[float]=None, source: Optional[str]=None, source_port: int=0, serial: int=0, use_udp: bool=False, keyalgorithm: Union[dns.name.Name, str]=dns.tsig.default_algorithm) -> Any:
    """Return a generator for the responses to a zone transfer.

    *where*, a ``str`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *zone*, a ``dns.name.Name`` or ``str``, the name of the zone to transfer.

    *rdtype*, an ``int`` or ``str``, the type of zone transfer.  The
    default is ``dns.rdatatype.AXFR``.  ``dns.rdatatype.IXFR`` can be
    used to do an incremental transfer instead.

    *rdclass*, an ``int`` or ``str``, the class of the zone transfer.
    The default is ``dns.rdataclass.IN``.

    *timeout*, a ``float``, the number of seconds to wait for each
    response message.  If None, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *keyring*, a ``dict``, the keyring to use for TSIG.

    *keyname*, a ``dns.name.Name`` or ``str``, the name of the TSIG
    key to use.

    *relativize*, a ``bool``.  If ``True``, all names in the zone will be
    relativized to the zone origin.  It is essential that the
    relativize setting matches the one specified to
    ``dns.zone.from_xfr()`` if using this generator to make a zone.

    *lifetime*, a ``float``, the total number of seconds to spend
    doing the transfer.  If ``None``, the default, then there is no
    limit on the time the transfer may take.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *serial*, an ``int``, the SOA serial number to use as the base for
    an IXFR diff sequence (only meaningful if *rdtype* is
    ``dns.rdatatype.IXFR``).

    *use_udp*, a ``bool``.  If ``True``, use UDP (only meaningful for IXFR).

    *keyalgorithm*, a ``dns.name.Name`` or ``str``, the TSIG algorithm to use.

    Raises on errors, and so does the generator.

    Returns a generator of ``dns.message.Message`` objects.
    """
    pass

class UDPMode(enum.IntEnum):
    """How should UDP be used in an IXFR from :py:func:`inbound_xfr()`?

    NEVER means "never use UDP; always use TCP"
    TRY_FIRST means "try to use UDP but fall back to TCP if needed"
    ONLY means "raise ``dns.xfr.UseTCP`` if trying UDP does not succeed"
    """
    NEVER = 0
    TRY_FIRST = 1
    ONLY = 2

def inbound_xfr(where: str, txn_manager: dns.transaction.TransactionManager, query: Optional[dns.message.Message]=None, port: int=53, timeout: Optional[float]=None, lifetime: Optional[float]=None, source: Optional[str]=None, source_port: int=0, udp_mode: UDPMode=UDPMode.NEVER) -> None:
    """Conduct an inbound transfer and apply it via a transaction from the
    txn_manager.

    *where*, a ``str`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *txn_manager*, a ``dns.transaction.TransactionManager``, the txn_manager
    for this transfer (typically a ``dns.zone.Zone``).

    *query*, the query to send.  If not supplied, a default query is
    constructed using information from the *txn_manager*.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *timeout*, a ``float``, the number of seconds to wait for each
    response message.  If None, the default, wait forever.

    *lifetime*, a ``float``, the total number of seconds to spend
    doing the transfer.  If ``None``, the default, then there is no
    limit on the time the transfer may take.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *udp_mode*, a ``dns.query.UDPMode``, determines how UDP is used
    for IXFRs.  The default is ``dns.UDPMode.NEVER``, i.e. only use
    TCP.  Other possibilities are ``dns.UDPMode.TRY_FIRST``, which
    means "try UDP but fallback to TCP if needed", and
    ``dns.UDPMode.ONLY``, which means "try UDP and raise
    ``dns.xfr.UseTCP`` if it does not succeed.

    Raises on errors.
    """
    pass
