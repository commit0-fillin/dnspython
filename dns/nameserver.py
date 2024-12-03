from typing import Optional, Union
from urllib.parse import urlparse
import dns.asyncbackend
import dns.asyncquery
import dns.inet
import dns.message
import dns.query

class Nameserver:

    def __init__(self):
        """
        Initialize the Nameserver base class.
        This is an abstract base class, so it doesn't need any attributes.
        """

    def __str__(self):
        raise NotImplementedError

class AddressAndPortNameserver(Nameserver):

    def __init__(self, address: str, port: int):
        super().__init__()
        self.address = address
        self.port = port

    def __str__(self):
        ns_kind = self.kind()
        return f'{ns_kind}:{self.address}@{self.port}'

class Do53Nameserver(AddressAndPortNameserver):

    def __init__(self, address: str, port: int=53):
        super().__init__(address, port)

class DoHNameserver(Nameserver):

    def __init__(self, url: str, bootstrap_address: Optional[str]=None, verify: Union[bool, str]=True, want_get: bool=False):
        super().__init__()
        self.url = url
        self.bootstrap_address = bootstrap_address
        self.verify = verify
        self.want_get = want_get

    def __str__(self):
        return self.url

class DoTNameserver(AddressAndPortNameserver):

    def __init__(self, address: str, port: int=853, hostname: Optional[str]=None, verify: Union[bool, str]=True):
        super().__init__(address, port)
        self.hostname = hostname
        self.verify = verify

class DoQNameserver(AddressAndPortNameserver):

    def __init__(self, address: str, port: int=853, verify: Union[bool, str]=True, server_hostname: Optional[str]=None):
        super().__init__(address, port)
        self.verify = verify
        self.server_hostname = server_hostname
