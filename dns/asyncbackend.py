from typing import Dict
import dns.exception
from dns._asyncbackend import Backend, DatagramSocket, Socket, StreamSocket
_default_backend = None
_backends: Dict[str, Backend] = {}
_no_sniffio = False

class AsyncLibraryNotFoundError(dns.exception.DNSException):
    pass

def get_backend(name: str) -> Backend:
    """Get the specified asynchronous backend.

    *name*, a ``str``, the name of the backend.  Currently the "trio"
    and "asyncio" backends are available.

    Raises NotImplementedError if an unknown backend name is specified.
    """
    if name not in _backends:
        if name == 'trio':
            from dns._trio_backend import Backend as TrioBackend
            _backends['trio'] = TrioBackend()
        elif name == 'asyncio':
            from dns._asyncio_backend import Backend as AsyncioBackend
            _backends['asyncio'] = AsyncioBackend()
        else:
            raise NotImplementedError(f'Unknown backend "{name}"')
    return _backends[name]

def sniff() -> str:
    """Attempt to determine the in-use asynchronous I/O library by using
    the ``sniffio`` module if it is available.

    Returns the name of the library, or raises AsyncLibraryNotFoundError
    if the library cannot be determined.
    """
    global _no_sniffio
    if not _no_sniffio:
        try:
            import sniffio
            library = sniffio.current_async_library()
            if library == 'trio':
                return 'trio'
            elif library == 'asyncio':
                return 'asyncio'
        except ImportError:
            _no_sniffio = True
        except sniffio.AsyncLibraryNotFoundError:
            pass
    raise AsyncLibraryNotFoundError('Unable to determine async library')

def get_default_backend() -> Backend:
    """Get the default backend, initializing it if necessary."""
    global _default_backend
    if _default_backend is None:
        try:
            name = sniff()
        except AsyncLibraryNotFoundError:
            name = 'asyncio'
        _default_backend = get_backend(name)
    return _default_backend

def set_default_backend(name: str) -> Backend:
    """Set the default backend.

    It's not normally necessary to call this method, as
    ``get_default_backend()`` will initialize the backend
    appropriately in many cases.  If ``sniffio`` is not installed, or
    in testing situations, this function allows the backend to be set
    explicitly.
    """
    global _default_backend
    _default_backend = get_backend(name)
    return _default_backend
