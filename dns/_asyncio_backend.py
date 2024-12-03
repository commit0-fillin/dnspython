"""asyncio library query support"""
import asyncio
import socket
import sys
import dns._asyncbackend
import dns._features
import dns.exception
import dns.inet
_is_win32 = sys.platform == 'win32'

class _DatagramProtocol:

    def __init__(self):
        self.transport = None
        self.recvfrom = None

class DatagramSocket(dns._asyncbackend.DatagramSocket):

    def __init__(self, family, transport, protocol):
        super().__init__(family)
        self.transport = transport
        self.protocol = protocol

class StreamSocket(dns._asyncbackend.StreamSocket):

    def __init__(self, af, reader, writer):
        self.family = af
        self.reader = reader
        self.writer = writer
if dns._features.have('doh'):
    import anyio
    import httpcore
    import httpcore._backends.anyio
    import httpx
    _CoreAsyncNetworkBackend = httpcore.AsyncNetworkBackend
    _CoreAnyIOStream = httpcore._backends.anyio.AnyIOStream
    from dns.query import _compute_times, _expiration_for_this_attempt, _remaining

    class _NetworkBackend(_CoreAsyncNetworkBackend):

        def __init__(self, resolver, local_port, bootstrap_address, family):
            super().__init__()
            self._local_port = local_port
            self._resolver = resolver
            self._bootstrap_address = bootstrap_address
            self._family = family
            if local_port != 0:
                raise NotImplementedError('the asyncio transport for HTTPX cannot set the local port')

    class _HTTPTransport(httpx.AsyncHTTPTransport):

        def __init__(self, *args, local_port=0, bootstrap_address=None, resolver=None, family=socket.AF_UNSPEC, **kwargs):
            if resolver is None:
                import dns.asyncresolver
                resolver = dns.asyncresolver.Resolver()
            super().__init__(*args, **kwargs)
            self._pool._network_backend = _NetworkBackend(resolver, local_port, bootstrap_address, family)
else:
    _HTTPTransport = dns._asyncbackend.NullTransport

class Backend(dns._asyncbackend.Backend):
    def __init__(self):
        super().__init__()
