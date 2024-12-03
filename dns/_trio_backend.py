"""trio async I/O library query support"""
import socket
import trio
import trio.socket
import dns._asyncbackend
import dns._features
import dns.exception
import dns.inet
if not dns._features.have('trio'):
    raise ImportError('trio not found or too old')
_lltuple = dns.inet.low_level_address_tuple

class DatagramSocket(dns._asyncbackend.DatagramSocket):

    def __init__(self, socket):
        super().__init__(socket.family)
        self.socket = socket

class StreamSocket(dns._asyncbackend.StreamSocket):

    def __init__(self, family, stream, tls=False):
        self.family = family
        self.stream = stream
        self.tls = tls
if dns._features.have('doh'):
    import httpcore
    import httpcore._backends.trio
    import httpx
    _CoreAsyncNetworkBackend = httpcore.AsyncNetworkBackend
    _CoreTrioStream = httpcore._backends.trio.TrioStream
    from dns.query import _compute_times, _expiration_for_this_attempt, _remaining

    class _NetworkBackend(_CoreAsyncNetworkBackend):

        def __init__(self, resolver, local_port, bootstrap_address, family):
            super().__init__()
            self._local_port = local_port
            self._resolver = resolver
            self._bootstrap_address = bootstrap_address
            self._family = family

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
