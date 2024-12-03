"""DNS stub resolver."""
import contextlib
import random
import socket
import sys
import threading
import time
import warnings
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse
import dns._ddr
import dns.edns
import dns.exception
import dns.flags
import dns.inet
import dns.ipv4
import dns.ipv6
import dns.message
import dns.name
import dns.nameserver
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.reversename
import dns.tsig
if sys.platform == 'win32':
    import dns.win32util

class NXDOMAIN(dns.exception.DNSException):
    """The DNS query name does not exist."""
    supp_kwargs = {'qnames', 'responses'}
    fmt = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __str__(self) -> str:
        if 'qnames' not in self.kwargs:
            return super().__str__()
        qnames = self.kwargs['qnames']
        if len(qnames) > 1:
            msg = 'None of DNS query names exist'
        else:
            msg = 'The DNS query name does not exist'
        qnames = ', '.join(map(str, qnames))
        return '{}: {}'.format(msg, qnames)

    @property
    def canonical_name(self):
        """Return the unresolved canonical name."""
        if 'qnames' not in self.kwargs:
            return None
        qnames = self.kwargs['qnames']
        if not qnames:
            return None
        return qnames[-1]

    def __add__(self, e_nx):
        """Augment by results from another NXDOMAIN exception."""
        qnames0 = list(self.kwargs.get('qnames', []))
        responses0 = dict(self.kwargs.get('responses', {}))
        responses1 = e_nx.kwargs.get('responses', {})
        for qname1 in e_nx.kwargs.get('qnames', []):
            if qname1 not in qnames0:
                qnames0.append(qname1)
            if qname1 in responses1:
                responses0[qname1] = responses1[qname1]
        return NXDOMAIN(qnames=qnames0, responses=responses0)

    def qnames(self):
        """All of the names that were tried.

        Returns a list of ``dns.name.Name``.
        """
        return self.kwargs.get('qnames', [])

    def responses(self):
        """A map from queried names to their NXDOMAIN responses.

        Returns a dict mapping a ``dns.name.Name`` to a
        ``dns.message.Message``.
        """
        return self.kwargs.get('responses', {})

    def response(self, qname):
        """The response for query *qname*.

        Returns a ``dns.message.Message``.
        """
        return self.responses().get(qname)

class YXDOMAIN(dns.exception.DNSException):
    """The DNS query name is too long after DNAME substitution."""
ErrorTuple = Tuple[Optional[str], bool, int, Union[Exception, str], Optional[dns.message.Message]]

def _errors_to_text(errors: List[ErrorTuple]) -> List[str]:
    """Turn a resolution errors trace into a list of text."""
    pass

class LifetimeTimeout(dns.exception.Timeout):
    """The resolution lifetime expired."""
    msg = 'The resolution lifetime expired.'
    fmt = '%s after {timeout:.3f} seconds: {errors}' % msg[:-1]
    supp_kwargs = {'timeout', 'errors'}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
Timeout = LifetimeTimeout

class NoAnswer(dns.exception.DNSException):
    """The DNS response does not contain an answer to the question."""
    fmt = 'The DNS response does not contain an answer to the question: {query}'
    supp_kwargs = {'response'}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class NoNameservers(dns.exception.DNSException):
    """All nameservers failed to answer the query.

    errors: list of servers and respective errors
    The type of errors is
    [(server IP address, any object convertible to string)].
    Non-empty errors list will add explanatory message ()
    """
    msg = 'All nameservers failed to answer the query.'
    fmt = '%s {query}: {errors}' % msg[:-1]
    supp_kwargs = {'request', 'errors'}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class NotAbsolute(dns.exception.DNSException):
    """An absolute domain name is required but a relative name was provided."""

class NoRootSOA(dns.exception.DNSException):
    """There is no SOA RR at the DNS root name. This should never happen!"""

class NoMetaqueries(dns.exception.DNSException):
    """DNS metaqueries are not allowed."""

class NoResolverConfiguration(dns.exception.DNSException):
    """Resolver configuration could not be read or specified no nameservers."""

class Answer:
    """DNS stub resolver answer.

    Instances of this class bundle up the result of a successful DNS
    resolution.

    For convenience, the answer object implements much of the sequence
    protocol, forwarding to its ``rrset`` attribute.  E.g.
    ``for a in answer`` is equivalent to ``for a in answer.rrset``.
    ``answer[i]`` is equivalent to ``answer.rrset[i]``, and
    ``answer[i:j]`` is equivalent to ``answer.rrset[i:j]``.

    Note that CNAMEs or DNAMEs in the response may mean that answer
    RRset's name might not be the query name.
    """

    def __init__(self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType, rdclass: dns.rdataclass.RdataClass, response: dns.message.QueryMessage, nameserver: Optional[str]=None, port: Optional[int]=None) -> None:
        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.response = response
        self.nameserver = nameserver
        self.port = port
        self.chaining_result = response.resolve_chaining()
        self.canonical_name = self.chaining_result.canonical_name
        self.rrset = self.chaining_result.answer
        self.expiration = time.time() + self.chaining_result.minimum_ttl

    def __getattr__(self, attr):
        if attr == 'name':
            return self.rrset.name
        elif attr == 'ttl':
            return self.rrset.ttl
        elif attr == 'covers':
            return self.rrset.covers
        elif attr == 'rdclass':
            return self.rrset.rdclass
        elif attr == 'rdtype':
            return self.rrset.rdtype
        else:
            raise AttributeError(attr)

    def __len__(self) -> int:
        return self.rrset and len(self.rrset) or 0

    def __iter__(self):
        return self.rrset and iter(self.rrset) or iter(tuple())

    def __getitem__(self, i):
        if self.rrset is None:
            raise IndexError
        return self.rrset[i]

    def __delitem__(self, i):
        if self.rrset is None:
            raise IndexError
        del self.rrset[i]

class Answers(dict):
    """A dict of DNS stub resolver answers, indexed by type."""

class HostAnswers(Answers):
    """A dict of DNS stub resolver answers to a host name lookup, indexed by
    type.
    """

class CacheStatistics:
    """Cache Statistics"""

    def __init__(self, hits: int=0, misses: int=0) -> None:
        self.hits = hits
        self.misses = misses

class CacheBase:

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.statistics = CacheStatistics()

    def reset_statistics(self) -> None:
        """Reset all statistics to zero."""
        with self.lock:
            self.statistics = CacheStatistics()

    def hits(self) -> int:
        """How many hits has the cache had?"""
        return self.statistics.hits

    def misses(self) -> int:
        """How many misses has the cache had?"""
        return self.statistics.misses

    def get_statistics_snapshot(self) -> CacheStatistics:
        """Return a consistent snapshot of all the statistics.

        If running with multiple threads, it's better to take a
        snapshot than to call statistics methods such as hits() and
        misses() individually.
        """
        with self.lock:
            return CacheStatistics(hits=self.statistics.hits, misses=self.statistics.misses)
CacheKey = Tuple[dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass]

class Cache(CacheBase):
    """Simple thread-safe DNS answer cache."""

    def __init__(self, cleaning_interval: float=300.0) -> None:
        """*cleaning_interval*, a ``float`` is the number of seconds between
        periodic cleanings.
        """
        super().__init__()
        self.data: Dict[CacheKey, Answer] = {}
        self.cleaning_interval = cleaning_interval
        self.next_cleaning: float = time.time() + self.cleaning_interval

    def _maybe_clean(self) -> None:
        """Clean the cache if it's time to do so."""
        now = time.time()
        if self.next_cleaning <= now:
            keys_to_delete = [k for k, v in self.data.items() if v.expiration <= now]
            for k in keys_to_delete:
                del self.data[k]
            self.next_cleaning = now + self.cleaning_interval

    def get(self, key: CacheKey) -> Optional[Answer]:
        """Get the answer associated with *key*.

        Returns None if no answer is cached for the key.

        *key*, a ``(dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass)``
        tuple whose values are the query name, rdtype, and rdclass respectively.

        Returns a ``dns.resolver.Answer`` or ``None``.
        """
        with self.lock:
            self._maybe_clean()
            answer = self.data.get(key)
            if answer is not None and answer.expiration > time.time():
                self.statistics.hits += 1
                return answer
            self.statistics.misses += 1
            return None

    def put(self, key: CacheKey, value: Answer) -> None:
        """Associate key and value in the cache.

        *key*, a ``(dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass)``
        tuple whose values are the query name, rdtype, and rdclass respectively.

        *value*, a ``dns.resolver.Answer``, the answer.
        """
        with self.lock:
            self._maybe_clean()
            self.data[key] = value

    def flush(self, key: Optional[CacheKey]=None) -> None:
        """Flush the cache.

        If *key* is not ``None``, only that item is flushed.  Otherwise the entire cache
        is flushed.

        *key*, a ``(dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass)``
        tuple whose values are the query name, rdtype, and rdclass respectively.
        """
        with self.lock:
            if key is not None:
                self.data.pop(key, None)
            else:
                self.data.clear()
            self.next_cleaning = time.time() + self.cleaning_interval

class LRUCacheNode:
    """LRUCache node."""

    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.hits = 0
        self.prev = self
        self.next = self

class LRUCache(CacheBase):
    """Thread-safe, bounded, least-recently-used DNS answer cache.

    This cache is better than the simple cache (above) if you're
    running a web crawler or other process that does a lot of
    resolutions.  The LRUCache has a maximum number of nodes, and when
    it is full, the least-recently used node is removed to make space
    for a new one.
    """

    def __init__(self, max_size: int=100000) -> None:
        """*max_size*, an ``int``, is the maximum number of nodes to cache;
        it must be greater than 0.
        """
        super().__init__()
        self.data: Dict[CacheKey, LRUCacheNode] = {}
        self.set_max_size(max_size)
        self.sentinel: LRUCacheNode = LRUCacheNode(None, None)
        self.sentinel.prev = self.sentinel
        self.sentinel.next = self.sentinel

    def get(self, key: CacheKey) -> Optional[Answer]:
        """Get the answer associated with *key*.

        Returns None if no answer is cached for the key.

        *key*, a ``(dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass)``
        tuple whose values are the query name, rdtype, and rdclass respectively.

        Returns a ``dns.resolver.Answer`` or ``None``.
        """
        with self.lock:
            node = self.data.get(key)
            if node is None:
                self.statistics.misses += 1
                return None
            if node.value.expiration <= time.time():
                self._delete_node(node)
                self.statistics.misses += 1
                return None
            node.hits += 1
            self._move_to_front(node)
            self.statistics.hits += 1
            return node.value

    def get_hits_for_key(self, key: CacheKey) -> int:
        """Return the number of cache hits associated with the specified key."""
        with self.lock:
            node = self.data.get(key)
            if node is None:
                return 0
            return node.hits

    def put(self, key: CacheKey, value: Answer) -> None:
        """Associate key and value in the cache.

        *key*, a ``(dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass)``
        tuple whose values are the query name, rdtype, and rdclass respectively.

        *value*, a ``dns.resolver.Answer``, the answer.
        """
        with self.lock:
            node = self.data.get(key)
            if node is not None:
                node.value = value
                node.hits += 1
                self._move_to_front(node)
            else:
                while len(self.data) >= self.max_size:
                    self._remove_least_recently_used()
                node = LRUCacheNode(key, value)
                self._add_front(node)
                self.data[key] = node

    def flush(self, key: Optional[CacheKey]=None) -> None:
        """Flush the cache.

        If *key* is not ``None``, only that item is flushed.  Otherwise the entire cache
        is flushed.

        *key*, a ``(dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass)``
        tuple whose values are the query name, rdtype, and rdclass respectively.
        """
        with self.lock:
            if key is not None:
                node = self.data.get(key)
                if node is not None:
                    self._delete_node(node)
            else:
                self.data.clear()
                self.sentinel.prev = self.sentinel
                self.sentinel.next = self.sentinel

class _Resolution:
    """Helper class for dns.resolver.Resolver.resolve().

    All of the "business logic" of resolution is encapsulated in this
    class, allowing us to have multiple resolve() implementations
    using different I/O schemes without copying all of the
    complicated logic.

    This class is a "friend" to dns.resolver.Resolver and manipulates
    resolver data structures directly.
    """

    def __init__(self, resolver: 'BaseResolver', qname: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str], rdclass: Union[dns.rdataclass.RdataClass, str], tcp: bool, raise_on_no_answer: bool, search: Optional[bool]) -> None:
        if isinstance(qname, str):
            qname = dns.name.from_text(qname, None)
        rdtype = dns.rdatatype.RdataType.make(rdtype)
        if dns.rdatatype.is_metatype(rdtype):
            raise NoMetaqueries
        rdclass = dns.rdataclass.RdataClass.make(rdclass)
        if dns.rdataclass.is_metaclass(rdclass):
            raise NoMetaqueries
        self.resolver = resolver
        self.qnames_to_try = resolver._get_qnames_to_try(qname, search)
        self.qnames = self.qnames_to_try[:]
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.tcp = tcp
        self.raise_on_no_answer = raise_on_no_answer
        self.nxdomain_responses: Dict[dns.name.Name, dns.message.QueryMessage] = {}
        self.qname = dns.name.empty
        self.nameservers: List[dns.nameserver.Nameserver] = []
        self.current_nameservers: List[dns.nameserver.Nameserver] = []
        self.errors: List[ErrorTuple] = []
        self.nameserver: Optional[dns.nameserver.Nameserver] = None
        self.tcp_attempt = False
        self.retry_with_tcp = False
        self.request: Optional[dns.message.QueryMessage] = None
        self.backoff = 0.0

    def next_request(self) -> Tuple[Optional[dns.message.QueryMessage], Optional[Answer]]:
        """Get the next request to send, and check the cache.

        Returns a (request, answer) tuple.  At most one of request or
        answer will not be None.
        """
        pass

class BaseResolver:
    """DNS stub resolver."""
    domain: dns.name.Name
    nameserver_ports: Dict[str, int]
    port: int
    search: List[dns.name.Name]
    use_search_by_default: bool
    timeout: float
    lifetime: float
    keyring: Optional[Any]
    keyname: Optional[Union[dns.name.Name, str]]
    keyalgorithm: Union[dns.name.Name, str]
    edns: int
    ednsflags: int
    ednsoptions: Optional[List[dns.edns.Option]]
    payload: int
    cache: Any
    flags: Optional[int]
    retry_servfail: bool
    rotate: bool
    ndots: Optional[int]
    _nameservers: Sequence[Union[str, dns.nameserver.Nameserver]]

    def __init__(self, filename: str='/etc/resolv.conf', configure: bool=True) -> None:
        """*filename*, a ``str`` or file object, specifying a file
        in standard /etc/resolv.conf format.  This parameter is meaningful
        only when *configure* is true and the platform is POSIX.

        *configure*, a ``bool``.  If True (the default), the resolver
        instance is configured in the normal fashion for the operating
        system the resolver is running on.  (I.e. by reading a
        /etc/resolv.conf file on POSIX systems and from the registry
        on Windows systems.)
        """
        self.reset()
        if configure:
            if sys.platform == 'win32':
                self.read_registry()
            elif filename:
                self.read_resolv_conf(filename)

    def reset(self) -> None:
        """Reset all resolver configuration to the defaults."""
        self.domain = dns.name.Name(labels=[])
        self.nameserver_ports = {}
        self.port = 53
        self.search = []
        self.use_search_by_default = True
        self.timeout = 2.0
        self.lifetime = 5.0
        self.keyring = None
        self.keyname = None
        self.keyalgorithm = dns.tsig.default_algorithm
        self.edns = -1
        self.ednsflags = 0
        self.payload = DEFAULT_EDNS_PAYLOAD
        self.cache = None
        self.flags = None
        self.retry_servfail = False
        self.rotate = False
        self.ndots = None
        self._nameservers = []

    def read_resolv_conf(self, f: Any) -> None:
        """Process *f* as a file in the /etc/resolv.conf format.  If f is
        a ``str``, it is used as the name of the file to open; otherwise it
        is treated as the file itself.

        Interprets the following items:

        - nameserver - name server IP address

        - domain - local domain name

        - search - search list for host-name lookup

        - options - supported options are rotate, timeout, edns0, and ndots

        """
        if isinstance(f, str):
            with open(f, 'r') as f_obj:
                self._read_resolv_conf(f_obj)
        else:
            self._read_resolv_conf(f)

    def _read_resolv_conf(self, f):
        for line in f:
            if line.startswith('#') or line.isspace():
                continue
            tokens = line.split()
            if len(tokens) < 2:
                continue
            if tokens[0] == 'nameserver':
                self.nameservers = tokens[1:]
            elif tokens[0] == 'domain':
                self.domain = dns.name.from_text(tokens[1])
            elif tokens[0] == 'search':
                self.search = [dns.name.from_text(token) for token in tokens[1:]]
            elif tokens[0] == 'options':
                for token in tokens[1:]:
                    if token == 'rotate':
                        self.rotate = True
                    elif token.startswith('timeout:'):
                        self.timeout = float(token.split(':')[1])
                    elif token == 'edns0':
                        self.use_edns()
                    elif token.startswith('ndots:'):
                        self.ndots = int(token.split(':')[1])

    def read_registry(self) -> None:
        """Extract resolver configuration from the Windows registry."""
        if sys.platform != 'win32':
            raise NotImplementedError("read_registry() is only supported on Windows")
    
        import winreg
    
        lm = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        try:
            tcp_params = winreg.OpenKey(lm, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters')
            try:
                self.domain = winreg.QueryValueEx(tcp_params, 'Domain')[0]
            except WindowsError:
                pass
            try:
                self.search = winreg.QueryValueEx(tcp_params, 'SearchList')[0].split(',')
            except WindowsError:
                pass
        
            interfaces = winreg.OpenKey(lm, r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces')
            for i in range(winreg.QueryInfoKey(interfaces)[0]):
                try:
                    interface_key = winreg.OpenKey(interfaces, winreg.EnumKey(interfaces, i))
                    try:
                        nameservers = winreg.QueryValueEx(interface_key, 'NameServer')[0].split(',')
                        self.nameservers.extend(nameservers)
                    except WindowsError:
                        pass
                except WindowsError:
                    pass
        finally:
            winreg.CloseKey(lm)

    def use_tsig(self, keyring: Any, keyname: Optional[Union[dns.name.Name, str]]=None, algorithm: Union[dns.name.Name, str]=dns.tsig.default_algorithm) -> None:
        """Add a TSIG signature to each query.

        The parameters are passed to ``dns.message.Message.use_tsig()``;
        see its documentation for details.
        """
        self.keyring = keyring
        self.keyname = keyname
        self.keyalgorithm = algorithm

    def use_edns(self, edns: Optional[Union[int, bool]]=0, ednsflags: int=0, payload: int=dns.message.DEFAULT_EDNS_PAYLOAD, options: Optional[List[dns.edns.Option]]=None) -> None:
        """Configure EDNS behavior.

        *edns*, an ``int``, is the EDNS level to use.  Specifying
        ``None``, ``False``, or ``-1`` means "do not use EDNS", and in this case
        the other parameters are ignored.  Specifying ``True`` is
        equivalent to specifying 0, i.e. "use EDNS0".

        *ednsflags*, an ``int``, the EDNS flag values.

        *payload*, an ``int``, is the EDNS sender's payload field, which is the
        maximum size of UDP datagram the sender can handle.  I.e. how big
        a response to this message can be.

        *options*, a list of ``dns.edns.Option`` objects or ``None``, the EDNS
        options.
        """
        if edns is None or edns is False:
            self.edns = -1
        elif edns is True:
            self.edns = 0
        else:
            self.edns = edns
        self.ednsflags = ednsflags
        self.payload = payload
        self.options = options

    def set_flags(self, flags: int) -> None:
        """Overrides the default flags with your own.

        *flags*, an ``int``, the message flags to use.
        """
        self.flags = flags

    @nameservers.setter
    def nameservers(self, nameservers: Sequence[Union[str, dns.nameserver.Nameserver]]) -> None:
        """
        *nameservers*, a ``list`` of nameservers, where a nameserver is either
        a string interpretable as a nameserver, or a ``dns.nameserver.Nameserver``
        instance.

        Raises ``ValueError`` if *nameservers* is not a list of nameservers.
        """
        nss = []
        for ns in nameservers:
            if isinstance(ns, str):
                nss.append(dns.nameserver.Do53Nameserver(ns))
            elif isinstance(ns, dns.nameserver.Nameserver):
                nss.append(ns)
            else:
                raise ValueError(f'invalid nameserver: {ns}')
        self._nameservers = nss

class Resolver(BaseResolver):
    """DNS stub resolver."""

    def resolve(self, qname: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.A, rdclass: Union[dns.rdataclass.RdataClass, str]=dns.rdataclass.IN, tcp: bool=False, source: Optional[str]=None, raise_on_no_answer: bool=True, source_port: int=0, lifetime: Optional[float]=None, search: Optional[bool]=None) -> Answer:
        """Query nameservers to find the answer to the question.

        The *qname*, *rdtype*, and *rdclass* parameters may be objects
        of the appropriate type, or strings that can be converted into objects
        of the appropriate type.

        *qname*, a ``dns.name.Name`` or ``str``, the query name.

        *rdtype*, an ``int`` or ``str``,  the query type.

        *rdclass*, an ``int`` or ``str``,  the query class.

        *tcp*, a ``bool``.  If ``True``, use TCP to make the query.

        *source*, a ``str`` or ``None``.  If not ``None``, bind to this IP
        address when making queries.

        *raise_on_no_answer*, a ``bool``.  If ``True``, raise
        ``dns.resolver.NoAnswer`` if there's no answer to the question.

        *source_port*, an ``int``, the port from which to send the message.

        *lifetime*, a ``float``, how many seconds a query should run
        before timing out.

        *search*, a ``bool`` or ``None``, determines whether the
        search list configured in the system's resolver configuration
        are used for relative names, and whether the resolver's domain
        may be added to relative names.  The default is ``None``,
        which causes the value of the resolver's
        ``use_search_by_default`` attribute to be used.

        Raises ``dns.resolver.LifetimeTimeout`` if no answers could be found
        in the specified lifetime.

        Raises ``dns.resolver.NXDOMAIN`` if the query name does not exist.

        Raises ``dns.resolver.YXDOMAIN`` if the query name is too long after
        DNAME substitution.

        Raises ``dns.resolver.NoAnswer`` if *raise_on_no_answer* is
        ``True`` and the query name exists but has no RRset of the
        desired type and class.

        Raises ``dns.resolver.NoNameservers`` if no non-broken
        nameservers are available to answer the question.

        Returns a ``dns.resolver.Answer`` instance.

        """
        resolution = _Resolution(self, qname, rdtype, rdclass, tcp, raise_on_no_answer, search)
        start = time.time()
        while True:
            (request, answer) = resolution.next_request()
            if answer:
                return answer
            if request is None:
                raise dns.resolver.NXDOMAIN(qnames=resolution.qnames, responses=resolution.nxdomain_responses)
            done = False
            while not done:
                for nameserver in self.nameservers:
                    try:
                        response = dns.query.udp(request, nameserver.address, timeout=self.timeout, port=nameserver.port, source=source, source_port=source_port)
                        if response.flags & dns.flags.TC:
                            if tcp:
                                raise dns.exception.FormError
                            response = dns.query.tcp(request, nameserver.address, timeout=self.timeout, port=nameserver.port, source=source, source_port=source_port)
                        if response.rcode() == dns.rcode.NOERROR or response.rcode() == dns.rcode.NXDOMAIN:
                            done = True
                            break
                    except dns.exception.Timeout:
                        continue
                if not done:
                    if time.time() - start > (lifetime or self.lifetime):
                        raise dns.resolver.LifetimeTimeout(timeout=self.lifetime, errors=resolution.errors)
            if response.rcode() == dns.rcode.NXDOMAIN:
                resolution.nxdomain_responses[resolution.qname] = response
            else:
                answer = dns.resolver.Answer(resolution.qname, rdtype, rdclass, response, nameserver.address)
                self.cache.put((resolution.qname, rdtype, rdclass), answer)
                return answer

    def query(self, qname: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.A, rdclass: Union[dns.rdataclass.RdataClass, str]=dns.rdataclass.IN, tcp: bool=False, source: Optional[str]=None, raise_on_no_answer: bool=True, source_port: int=0, lifetime: Optional[float]=None) -> Answer:
        """Query nameservers to find the answer to the question.

        This method calls resolve() with ``search=True``, and is
        provided for backwards compatibility with prior versions of
        dnspython.  See the documentation for the resolve() method for
        further details.
        """
        return self.resolve(qname, rdtype, rdclass, tcp, source, raise_on_no_answer, source_port, lifetime, search=True)

    def resolve_address(self, ipaddr: str, *args: Any, **kwargs: Any) -> Answer:
        """Use a resolver to run a reverse query for PTR records.

        This utilizes the resolve() method to perform a PTR lookup on the
        specified IP address.

        *ipaddr*, a ``str``, the IPv4 or IPv6 address you want to get
        the PTR record for.

        All other arguments that can be passed to the resolve() function
        except for rdtype and rdclass are also supported by this
        function.
        """
        return self.resolve(dns.reversename.from_address(ipaddr), rdtype='PTR', *args, **kwargs)

    def resolve_name(self, name: Union[dns.name.Name, str], family: int=socket.AF_UNSPEC, **kwargs: Any) -> HostAnswers:
        """Use a resolver to query for address records.

        This utilizes the resolve() method to perform A and/or AAAA lookups on
        the specified name.

        *qname*, a ``dns.name.Name`` or ``str``, the name to resolve.

        *family*, an ``int``, the address family.  If socket.AF_UNSPEC
        (the default), both A and AAAA records will be retrieved.

        All other arguments that can be passed to the resolve() function
        except for rdtype and rdclass are also supported by this
        function.
        """
        answers = HostAnswers()
        if family == socket.AF_INET or family == socket.AF_UNSPEC:
            try:
                answer = self.resolve(name, rdtype='A', **kwargs)
                answers[dns.rdatatype.A] = answer
            except dns.resolver.NoAnswer:
                pass
        if family == socket.AF_INET6 or family == socket.AF_UNSPEC:
            try:
                answer = self.resolve(name, rdtype='AAAA', **kwargs)
                answers[dns.rdatatype.AAAA] = answer
            except dns.resolver.NoAnswer:
                pass
        if len(answers) == 0:
            raise dns.resolver.NoAnswer(response=None)
        return answers

    def canonical_name(self, name: Union[dns.name.Name, str]) -> dns.name.Name:
        """Determine the canonical name of *name*.

        The canonical name is the name the resolver uses for queries
        after all CNAME and DNAME renamings have been applied.

        *name*, a ``dns.name.Name`` or ``str``, the query name.

        This method can raise any exception that ``resolve()`` can
        raise, other than ``dns.resolver.NoAnswer`` and
        ``dns.resolver.NXDOMAIN``.

        Returns a ``dns.name.Name``.
        """
        try:
            answer = self.resolve(name, rdtype='CNAME')
            cname = answer.rrset[0].target
            return self.canonical_name(cname)
        except dns.resolver.NoAnswer:
            return dns.name.from_text(name)

    def try_ddr(self, lifetime: float=5.0) -> None:
        """Try to update the resolver's nameservers using Discovery of Designated
        Resolvers (DDR).  If successful, the resolver will subsequently use
        DNS-over-HTTPS or DNS-over-TLS for future queries.

        *lifetime*, a float, is the maximum time to spend attempting DDR.  The default
        is 5 seconds.

        If the SVCB query is successful and results in a non-empty list of nameservers,
        then the resolver's nameservers are set to the returned servers in priority
        order.

        The current implementation does not use any address hints from the SVCB record,
        nor does it resolve addresses for the SCVB target name, rather it assumes that
        the bootstrap nameserver will always be one of the addresses and uses it.
        A future revision to the code may offer fuller support.  The code verifies that
        the bootstrap nameserver is in the Subject Alternative Name field of the
        TLS certficate.
        """
        import dns._ddr
    
        try:
            answer = self.resolve('_dns.resolver.arpa', 'SVCB', lifetime=lifetime)
        except dns.resolver.NXDOMAIN:
            return
        except dns.exception.Timeout:
            return

        nameservers = dns._ddr._get_nameservers_sync(answer, lifetime)
        if nameservers:
            self.nameservers = nameservers
default_resolver: Optional[Resolver] = None

def get_default_resolver() -> Resolver:
    """Get the default resolver, initializing it if necessary."""
    global default_resolver
    if default_resolver is None:
        default_resolver = Resolver()
    return default_resolver

def reset_default_resolver() -> None:
    """Re-initialize default resolver.

    Note that the resolver configuration (i.e. /etc/resolv.conf on UNIX
    systems) will be re-read immediately.
    """
    global default_resolver
    default_resolver = None
    get_default_resolver()

def resolve(qname: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.A, rdclass: Union[dns.rdataclass.RdataClass, str]=dns.rdataclass.IN, tcp: bool=False, source: Optional[str]=None, raise_on_no_answer: bool=True, source_port: int=0, lifetime: Optional[float]=None, search: Optional[bool]=None) -> Answer:
    """Query nameservers to find the answer to the question.

    This is a convenience function that uses the default resolver
    object to make the query.

    See ``dns.resolver.Resolver.resolve`` for more information on the
    parameters.
    """
    return get_default_resolver().resolve(qname, rdtype, rdclass, tcp, source,
                                          raise_on_no_answer, source_port,
                                          lifetime, search)

def query(qname: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.A, rdclass: Union[dns.rdataclass.RdataClass, str]=dns.rdataclass.IN, tcp: bool=False, source: Optional[str]=None, raise_on_no_answer: bool=True, source_port: int=0, lifetime: Optional[float]=None) -> Answer:
    """Query nameservers to find the answer to the question.

    This method calls resolve() with ``search=True``, and is
    provided for backwards compatibility with prior versions of
    dnspython.  See the documentation for the resolve() method for
    further details.
    """
    return resolve(qname, rdtype, rdclass, tcp, source, raise_on_no_answer,
                   source_port, lifetime, search=True)

def resolve_address(ipaddr: str, *args: Any, **kwargs: Any) -> Answer:
    """Use a resolver to run a reverse query for PTR records.

    See ``dns.resolver.Resolver.resolve_address`` for more information on the
    parameters.
    """
    return get_default_resolver().resolve_address(ipaddr, *args, **kwargs)

def resolve_name(name: Union[dns.name.Name, str], family: int=socket.AF_UNSPEC, **kwargs: Any) -> HostAnswers:
    """Use a resolver to query for address records.

    See ``dns.resolver.Resolver.resolve_name`` for more information on the
    parameters.
    """
    return get_default_resolver().resolve_name(name, family, **kwargs)

def canonical_name(name: Union[dns.name.Name, str]) -> dns.name.Name:
    """Determine the canonical name of *name*.

    See ``dns.resolver.Resolver.canonical_name`` for more information on the
    parameters and possible exceptions.
    """
    return get_default_resolver().canonical_name(name)

def try_ddr(lifetime: float=5.0) -> None:
    """Try to update the default resolver's nameservers using Discovery of Designated
    Resolvers (DDR).  If successful, the resolver will subsequently use
    DNS-over-HTTPS or DNS-over-TLS for future queries.

    See :py:func:`dns.resolver.Resolver.try_ddr` for more information.
    """
    get_default_resolver().try_ddr(lifetime)

def zone_for_name(name: Union[dns.name.Name, str], rdclass: dns.rdataclass.RdataClass=dns.rdataclass.IN, tcp: bool=False, resolver: Optional[Resolver]=None, lifetime: Optional[float]=None) -> dns.name.Name:
    """Find the name of the zone which contains the specified name.

    *name*, an absolute ``dns.name.Name`` or ``str``, the query name.

    *rdclass*, an ``int``, the query class.

    *tcp*, a ``bool``.  If ``True``, use TCP to make the query.

    *resolver*, a ``dns.resolver.Resolver`` or ``None``, the resolver to use.
    If ``None``, the default, then the default resolver is used.

    *lifetime*, a ``float``, the total time to allow for the queries needed
    to determine the zone.  If ``None``, the default, then only the individual
    query limits of the resolver apply.

    Raises ``dns.resolver.NoRootSOA`` if there is no SOA RR at the DNS
    root.  (This is only likely to happen if you're using non-default
    root servers in your network and they are misconfigured.)

    Raises ``dns.resolver.LifetimeTimeout`` if the answer could not be
    found in the allotted lifetime.

    Returns a ``dns.name.Name``.
    """
    if resolver is None:
        resolver = get_default_resolver()
    if isinstance(name, str):
        name = dns.name.from_text(name, dns.name.root)
    if not name.is_absolute():
        raise dns.resolver.NotAbsolute(name)
    start = time.time()
    while 1:
        try:
            answer = resolver.resolve(name, dns.rdatatype.SOA, rdclass, tcp=tcp,
                                      lifetime=_remaining(start, lifetime))
            if answer.rrset.name == name:
                return name
            # otherwise we were CNAMEd or DNAMEd and need to look higher
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        try:
            name = name.parent()
        except dns.name.NoParent:
            raise dns.resolver.NoRootSOA

def make_resolver_at(where: Union[dns.name.Name, str], port: int=53, family: int=socket.AF_UNSPEC, resolver: Optional[Resolver]=None) -> Resolver:
    """Make a stub resolver using the specified destination as the full resolver.

    *where*, a ``dns.name.Name`` or ``str`` the domain name or IP address of the
    full resolver.

    *port*, an ``int``, the port to use.  If not specified, the default is 53.

    *family*, an ``int``, the address family to use.  This parameter is used if
    *where* is not an address.  The default is ``socket.AF_UNSPEC`` in which case
    the first address returned by ``resolve_name()`` will be used, otherwise the
    first address of the specified family will be used.

    *resolver*, a ``dns.resolver.Resolver`` or ``None``, the resolver to use for
    resolution of hostnames.  If not specified, the default resolver will be used.

    Returns a ``dns.resolver.Resolver`` or raises an exception.
    """
    if resolver is None:
        resolver = get_default_resolver()
    
    if dns.inet.is_address(where):
        nameserver = where
    else:
        answers = resolver.resolve_name(where, family)
        if family == socket.AF_UNSPEC:
            nameserver = answers[0].address
        else:
            for answer in answers:
                if answer.rdtype == dns.rdatatype.A and family == socket.AF_INET:
                    nameserver = answer.address
                    break
                elif answer.rdtype == dns.rdatatype.AAAA and family == socket.AF_INET6:
                    nameserver = answer.address
                    break
            else:
                raise dns.resolver.NoAnswer

    new_resolver = Resolver()
    new_resolver.nameservers = [nameserver]
    new_resolver.port = port
    return new_resolver

def resolve_at(where: Union[dns.name.Name, str], qname: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.A, rdclass: Union[dns.rdataclass.RdataClass, str]=dns.rdataclass.IN, tcp: bool=False, source: Optional[str]=None, raise_on_no_answer: bool=True, source_port: int=0, lifetime: Optional[float]=None, search: Optional[bool]=None, port: int=53, family: int=socket.AF_UNSPEC, resolver: Optional[Resolver]=None) -> Answer:
    """Query nameservers to find the answer to the question.

    This is a convenience function that calls ``dns.resolver.make_resolver_at()`` to
    make a resolver, and then uses it to resolve the query.

    See ``dns.resolver.Resolver.resolve`` for more information on the resolution
    parameters, and ``dns.resolver.make_resolver_at`` for information about the resolver
    parameters *where*, *port*, *family*, and *resolver*.

    If making more than one query, it is more efficient to call
    ``dns.resolver.make_resolver_at()`` and then use that resolver for the queries
    instead of calling ``resolve_at()`` multiple times.
    """
    resolver_at = make_resolver_at(where, port, family, resolver)
    return resolver_at.resolve(qname, rdtype, rdclass, tcp, source,
                               raise_on_no_answer, source_port, lifetime, search)
_protocols_for_socktype = {socket.SOCK_DGRAM: [socket.SOL_UDP], socket.SOCK_STREAM: [socket.SOL_TCP]}
_resolver = None
_original_getaddrinfo = socket.getaddrinfo
_original_getnameinfo = socket.getnameinfo
_original_getfqdn = socket.getfqdn
_original_gethostbyname = socket.gethostbyname
_original_gethostbyname_ex = socket.gethostbyname_ex
_original_gethostbyaddr = socket.gethostbyaddr

def override_system_resolver(resolver: Optional[Resolver]=None) -> None:
    """Override the system resolver routines in the socket module with
    versions which use dnspython's resolver.

    This can be useful in testing situations where you want to control
    the resolution behavior of python code without having to change
    the system's resolver settings (e.g. /etc/resolv.conf).

    The resolver to use may be specified; if it's not, the default
    resolver will be used.

    resolver, a ``dns.resolver.Resolver`` or ``None``, the resolver to use.
    """
    if resolver is None:
        resolver = get_default_resolver()
    global _resolver
    _resolver = resolver
    socket.getaddrinfo = _getaddrinfo
    socket.getnameinfo = _getnameinfo
    socket.getfqdn = _getfqdn
    socket.gethostbyname = _gethostbyname
    socket.gethostbyname_ex = _gethostbyname_ex
    socket.gethostbyaddr = _gethostbyaddr

def restore_system_resolver() -> None:
    """Undo the effects of prior override_system_resolver()."""
    global _resolver
    _resolver = None
    socket.getaddrinfo = _original_getaddrinfo
    socket.getnameinfo = _original_getnameinfo
    socket.getfqdn = _original_getfqdn
    socket.gethostbyname = _original_gethostbyname
    socket.gethostbyname_ex = _original_gethostbyname_ex
    socket.gethostbyaddr = _original_gethostbyaddr
