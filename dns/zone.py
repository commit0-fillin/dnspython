"""DNS Zones."""
import contextlib
import io
import os
import struct
from typing import Any, Callable, Iterable, Iterator, List, MutableMapping, Optional, Set, Tuple, Union
import dns.exception
import dns.grange
import dns.immutable
import dns.name
import dns.node
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.ZONEMD
import dns.rrset
import dns.tokenizer
import dns.transaction
import dns.ttl
import dns.zonefile
from dns.zonetypes import DigestHashAlgorithm, DigestScheme, _digest_hashers

class BadZone(dns.exception.DNSException):
    """The DNS zone is malformed."""

class NoSOA(BadZone):
    """The DNS zone has no SOA RR at its origin."""

class NoNS(BadZone):
    """The DNS zone has no NS RRset at its origin."""

class UnknownOrigin(BadZone):
    """The DNS zone's origin is unknown."""

class UnsupportedDigestScheme(dns.exception.DNSException):
    """The zone digest's scheme is unsupported."""

class UnsupportedDigestHashAlgorithm(dns.exception.DNSException):
    """The zone digest's origin is unsupported."""

class NoDigest(dns.exception.DNSException):
    """The DNS zone has no ZONEMD RRset at its origin."""

class DigestVerificationFailure(dns.exception.DNSException):
    """The ZONEMD digest failed to verify."""

class Zone(dns.transaction.TransactionManager):
    """A DNS zone.

    A ``Zone`` is a mapping from names to nodes.  The zone object may be
    treated like a Python dictionary, e.g. ``zone[name]`` will retrieve
    the node associated with that name.  The *name* may be a
    ``dns.name.Name object``, or it may be a string.  In either case,
    if the name is relative it is treated as relative to the origin of
    the zone.
    """
    node_factory: Callable[[], dns.node.Node] = dns.node.Node
    map_factory: Callable[[], MutableMapping[dns.name.Name, dns.node.Node]] = dict
    writable_version_factory: Optional[Callable[[], 'WritableVersion']] = None
    immutable_version_factory: Optional[Callable[[], 'ImmutableVersion']] = None
    __slots__ = ['rdclass', 'origin', 'nodes', 'relativize']

    def __init__(self, origin: Optional[Union[dns.name.Name, str]], rdclass: dns.rdataclass.RdataClass=dns.rdataclass.IN, relativize: bool=True):
        """Initialize a zone object.

        *origin* is the origin of the zone.  It may be a ``dns.name.Name``,
        a ``str``, or ``None``.  If ``None``, then the zone's origin will
        be set by the first ``$ORIGIN`` line in a zone file.

        *rdclass*, an ``int``, the zone's rdata class; the default is class IN.

        *relativize*, a ``bool``, determine's whether domain names are
        relativized to the zone's origin.  The default is ``True``.
        """
        if origin is not None:
            if isinstance(origin, str):
                origin = dns.name.from_text(origin)
            elif not isinstance(origin, dns.name.Name):
                raise ValueError('origin parameter must be convertible to a DNS name')
            if not origin.is_absolute():
                raise ValueError('origin parameter must be an absolute name')
        self.origin = origin
        self.rdclass = rdclass
        self.nodes: MutableMapping[dns.name.Name, dns.node.Node] = self.map_factory()
        self.relativize = relativize

    def __eq__(self, other):
        """Two zones are equal if they have the same origin, class, and
        nodes.

        Returns a ``bool``.
        """
        if not isinstance(other, Zone):
            return False
        if self.rdclass != other.rdclass or self.origin != other.origin or self.nodes != other.nodes:
            return False
        return True

    def __ne__(self, other):
        """Are two zones not equal?

        Returns a ``bool``.
        """
        return not self.__eq__(other)

    def __getitem__(self, key):
        key = self._validate_name(key)
        return self.nodes[key]

    def __setitem__(self, key, value):
        key = self._validate_name(key)
        self.nodes[key] = value

    def __delitem__(self, key):
        key = self._validate_name(key)
        del self.nodes[key]

    def __iter__(self):
        return self.nodes.__iter__()

    def __contains__(self, key):
        key = self._validate_name(key)
        return key in self.nodes

    def find_node(self, name: Union[dns.name.Name, str], create: bool=False) -> dns.node.Node:
        """Find a node in the zone, possibly creating it.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.node.Node``.
        """
        if isinstance(name, str):
            name = dns.name.from_text(name, self.origin)
        if self.relativize:
            name = name.relativize(self.origin)
        if not name.is_subdomain(self.origin):
            raise KeyError("name is not a subdomain of the zone origin")
        node = self.nodes.get(name)
        if node is None and create:
            node = self.node_factory()
            self.nodes[name] = node
        elif node is None:
            raise KeyError("node '%s' does not exist" % name)
        return node

    def get_node(self, name: Union[dns.name.Name, str], create: bool=False) -> Optional[dns.node.Node]:
        """Get a node in the zone, possibly creating it.

        This method is like ``find_node()``, except it returns None instead
        of raising an exception if the node does not exist and creation
        has not been requested.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Returns a ``dns.node.Node`` or ``None``.
        """
        try:
            return self.find_node(name, create)
        except KeyError:
            return None

    def delete_node(self, name: Union[dns.name.Name, str]) -> None:
        """Delete the specified node if it exists.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        It is not an error if the node does not exist.
        """
        if isinstance(name, str):
            name = dns.name.from_text(name, self.origin)
        if self.relativize:
            name = name.relativize(self.origin)
        if name in self.nodes:
            del self.nodes[name]

    def find_rdataset(self, name: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str], covers: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.NONE, create: bool=False) -> dns.rdataset.Rdataset:
        """Look for an rdataset with the specified name and type in the zone,
        and return an rdataset encapsulating it.

        The rdataset returned is not a copy; changes to it will change
        the zone.

        KeyError is raised if the name or type are not found.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, a ``dns.rdatatype.RdataType`` or ``str``, the rdata type desired.

        *covers*, a ``dns.rdatatype.RdataType`` or ``str`` the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.rdataset.Rdataset``.
        """
        node = self.find_node(name, create)
        return node.find_rdataset(self.rdclass, rdtype, covers, create)

    def get_rdataset(self, name: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str], covers: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.NONE, create: bool=False) -> Optional[dns.rdataset.Rdataset]:
        """Look for an rdataset with the specified name and type in the zone.

        This method is like ``find_rdataset()``, except it returns None instead
        of raising an exception if the rdataset does not exist and creation
        has not been requested.

        The rdataset returned is not a copy; changes to it will change
        the zone.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, a ``dns.rdatatype.RdataType`` or ``str``, the rdata type desired.

        *covers*, a ``dns.rdatatype.RdataType`` or ``str``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.rdataset.Rdataset`` or ``None``.
        """
        pass

    def delete_rdataset(self, name: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str], covers: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.NONE) -> None:
        """Delete the rdataset matching *rdtype* and *covers*, if it
        exists at the node specified by *name*.

        It is not an error if the node does not exist, or if there is no matching
        rdataset at the node.

        If the node has no rdatasets after the deletion, it will itself be deleted.

        *name*: the name of the node to find. The value may be a ``dns.name.Name`` or a
        ``str``.  If absolute, the name must be a subdomain of the zone's origin.  If
        ``zone.relativize`` is ``True``, then the name will be relativized.

        *rdtype*, a ``dns.rdatatype.RdataType`` or ``str``, the rdata type desired.

        *covers*, a ``dns.rdatatype.RdataType`` or ``str`` or ``None``, the covered
        type. Usually this value is ``dns.rdatatype.NONE``, but if the rdtype is
        ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``, then the covers value will be
        the rdata type the SIG/RRSIG covers.  The library treats the SIG and RRSIG types
        as if they were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA). This
        makes RRSIGs much easier to work with than if RRSIGs covering different rdata
        types were aggregated into a single RRSIG rdataset.
        """
        pass

    def replace_rdataset(self, name: Union[dns.name.Name, str], replacement: dns.rdataset.Rdataset) -> None:
        """Replace an rdataset at name.

        It is not an error if there is no rdataset matching I{replacement}.

        Ownership of the *replacement* object is transferred to the zone;
        in other words, this method does not store a copy of *replacement*
        at the node, it stores *replacement* itself.

        If the node does not exist, it is created.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *replacement*, a ``dns.rdataset.Rdataset``, the replacement rdataset.
        """
        pass

    def find_rrset(self, name: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str], covers: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.NONE) -> dns.rrset.RRset:
        """Look for an rdataset with the specified name and type in the zone,
        and return an RRset encapsulating it.

        This method is less efficient than the similar
        ``find_rdataset()`` because it creates an RRset instead of
        returning the matching rdataset.  It may be more convenient
        for some uses since it returns an object which binds the owner
        name to the rdataset.

        This method may not be used to create new nodes or rdatasets;
        use ``find_rdataset`` instead.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, a ``dns.rdatatype.RdataType`` or ``str``, the rdata type desired.

        *covers*, a ``dns.rdatatype.RdataType`` or ``str``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.rrset.RRset`` or ``None``.
        """
        pass

    def get_rrset(self, name: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str], covers: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.NONE) -> Optional[dns.rrset.RRset]:
        """Look for an rdataset with the specified name and type in the zone,
        and return an RRset encapsulating it.

        This method is less efficient than the similar ``get_rdataset()``
        because it creates an RRset instead of returning the matching
        rdataset.  It may be more convenient for some uses since it
        returns an object which binds the owner name to the rdataset.

        This method may not be used to create new nodes or rdatasets;
        use ``get_rdataset()`` instead.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, a ``dns.rdataset.Rdataset`` or ``str``, the rdata type desired.

        *covers*, a ``dns.rdataset.Rdataset`` or ``str``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Returns a ``dns.rrset.RRset`` or ``None``.
        """
        pass

    def iterate_rdatasets(self, rdtype: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.ANY, covers: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.NONE) -> Iterator[Tuple[dns.name.Name, dns.rdataset.Rdataset]]:
        """Return a generator which yields (name, rdataset) tuples for
        all rdatasets in the zone which have the specified *rdtype*
        and *covers*.  If *rdtype* is ``dns.rdatatype.ANY``, the default,
        then all rdatasets will be matched.

        *rdtype*, a ``dns.rdataset.Rdataset`` or ``str``, the rdata type desired.

        *covers*, a ``dns.rdataset.Rdataset`` or ``str``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.
        """
        pass

    def iterate_rdatas(self, rdtype: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.ANY, covers: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.NONE) -> Iterator[Tuple[dns.name.Name, int, dns.rdata.Rdata]]:
        """Return a generator which yields (name, ttl, rdata) tuples for
        all rdatas in the zone which have the specified *rdtype*
        and *covers*.  If *rdtype* is ``dns.rdatatype.ANY``, the default,
        then all rdatas will be matched.

        *rdtype*, a ``dns.rdataset.Rdataset`` or ``str``, the rdata type desired.

        *covers*, a ``dns.rdataset.Rdataset`` or ``str``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.
        """
        pass

    def to_file(self, f: Any, sorted: bool=True, relativize: bool=True, nl: Optional[str]=None, want_comments: bool=False, want_origin: bool=False) -> None:
        """Write a zone to a file.

        *f*, a file or `str`.  If *f* is a string, it is treated
        as the name of a file to open.

        *sorted*, a ``bool``.  If True, the default, then the file
        will be written with the names sorted in DNSSEC order from
        least to greatest.  Otherwise the names will be written in
        whatever order they happen to have in the zone's dictionary.

        *relativize*, a ``bool``.  If True, the default, then domain
        names in the output will be relativized to the zone's origin
        if possible.

        *nl*, a ``str`` or None.  The end of line string.  If not
        ``None``, the output will use the platform's native
        end-of-line marker (i.e. LF on POSIX, CRLF on Windows).

        *want_comments*, a ``bool``.  If ``True``, emit end-of-line comments
        as part of writing the file.  If ``False``, the default, do not
        emit them.

        *want_origin*, a ``bool``.  If ``True``, emit a $ORIGIN line at
        the start of the file.  If ``False``, the default, do not emit
        one.
        """
        pass

    def to_text(self, sorted: bool=True, relativize: bool=True, nl: Optional[str]=None, want_comments: bool=False, want_origin: bool=False) -> str:
        """Return a zone's text as though it were written to a file.

        *sorted*, a ``bool``.  If True, the default, then the file
        will be written with the names sorted in DNSSEC order from
        least to greatest.  Otherwise the names will be written in
        whatever order they happen to have in the zone's dictionary.

        *relativize*, a ``bool``.  If True, the default, then domain
        names in the output will be relativized to the zone's origin
        if possible.

        *nl*, a ``str`` or None.  The end of line string.  If not
        ``None``, the output will use the platform's native
        end-of-line marker (i.e. LF on POSIX, CRLF on Windows).

        *want_comments*, a ``bool``.  If ``True``, emit end-of-line comments
        as part of writing the file.  If ``False``, the default, do not
        emit them.

        *want_origin*, a ``bool``.  If ``True``, emit a $ORIGIN line at
        the start of the output.  If ``False``, the default, do not emit
        one.

        Returns a ``str``.
        """
        pass

    def check_origin(self) -> None:
        """Do some simple checking of the zone's origin.

        Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

        Raises ``dns.zone.NoNS`` if there is no NS RRset.

        Raises ``KeyError`` if there is no origin node.
        """
        pass

    def get_soa(self, txn: Optional[dns.transaction.Transaction]=None) -> dns.rdtypes.ANY.SOA.SOA:
        """Get the zone SOA rdata.

        Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

        Returns a ``dns.rdtypes.ANY.SOA.SOA`` Rdata.
        """
        pass

class VersionedNode(dns.node.Node):
    __slots__ = ['id']

    def __init__(self):
        super().__init__()
        self.id = 0

@dns.immutable.immutable
class ImmutableVersionedNode(VersionedNode):

    def __init__(self, node):
        super().__init__()
        self.id = node.id
        self.rdatasets = tuple([dns.rdataset.ImmutableRdataset(rds) for rds in node.rdatasets])

class Version:

    def __init__(self, zone: Zone, id: int, nodes: Optional[MutableMapping[dns.name.Name, dns.node.Node]]=None, origin: Optional[dns.name.Name]=None):
        self.zone = zone
        self.id = id
        if nodes is not None:
            self.nodes = nodes
        else:
            self.nodes = zone.map_factory()
        self.origin = origin

class WritableVersion(Version):

    def __init__(self, zone: Zone, replacement: bool=False):
        id = zone._get_next_version_id()
        super().__init__(zone, id)
        if not replacement:
            self.nodes.update(zone.nodes)
        self.origin = zone.origin
        self.changed: Set[dns.name.Name] = set()

@dns.immutable.immutable
class ImmutableVersion(Version):

    def __init__(self, version: WritableVersion):
        super().__init__(version.zone, True)
        self.id = version.id
        self.origin = version.origin
        for name in version.changed:
            node = version.nodes.get(name)
            if node:
                version.nodes[name] = ImmutableVersionedNode(node)
        self.nodes = dns.immutable.Dict(version.nodes, True, self.zone.map_factory)

class Transaction(dns.transaction.Transaction):

    def __init__(self, zone, replacement, version=None, make_immutable=False):
        read_only = version is not None
        super().__init__(zone, replacement, read_only)
        self.version = version
        self.make_immutable = make_immutable

def from_text(text: str, origin: Optional[Union[dns.name.Name, str]]=None, rdclass: dns.rdataclass.RdataClass=dns.rdataclass.IN, relativize: bool=True, zone_factory: Any=Zone, filename: Optional[str]=None, allow_include: bool=False, check_origin: bool=True, idna_codec: Optional[dns.name.IDNACodec]=None, allow_directives: Union[bool, Iterable[str]]=True) -> Zone:
    """Build a zone object from a zone file format string.

    *text*, a ``str``, the zone file format input.

    *origin*, a ``dns.name.Name``, a ``str``, or ``None``.  The origin
    of the zone; if not specified, the first ``$ORIGIN`` statement in the
    zone file will determine the origin of the zone.

    *rdclass*, a ``dns.rdataclass.RdataClass``, the zone's rdata class; the default is
    class IN.

    *relativize*, a ``bool``, determine's whether domain names are
    relativized to the zone's origin.  The default is ``True``.

    *zone_factory*, the zone factory to use or ``None``.  If ``None``, then
    ``dns.zone.Zone`` will be used.  The value may be any class or callable
    that returns a subclass of ``dns.zone.Zone``.

    *filename*, a ``str`` or ``None``, the filename to emit when
    describing where an error occurred; the default is ``'<string>'``.

    *allow_include*, a ``bool``.  If ``True``, the default, then ``$INCLUDE``
    directives are permitted.  If ``False``, then encoutering a ``$INCLUDE``
    will raise a ``SyntaxError`` exception.

    *check_origin*, a ``bool``.  If ``True``, the default, then sanity
    checks of the origin node will be made by calling the zone's
    ``check_origin()`` method.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    *allow_directives*, a ``bool`` or an iterable of `str`.  If ``True``, the default,
    then directives are permitted, and the *allow_include* parameter controls whether
    ``$INCLUDE`` is permitted.  If ``False`` or an empty iterable, then no directive
    processing is done and any directive-like text will be treated as a regular owner
    name.  If a non-empty iterable, then only the listed directives (including the
    ``$``) are allowed.

    Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

    Raises ``dns.zone.NoNS`` if there is no NS RRset.

    Raises ``KeyError`` if there is no origin node.

    Returns a subclass of ``dns.zone.Zone``.
    """
    pass

def from_file(f: Any, origin: Optional[Union[dns.name.Name, str]]=None, rdclass: dns.rdataclass.RdataClass=dns.rdataclass.IN, relativize: bool=True, zone_factory: Any=Zone, filename: Optional[str]=None, allow_include: bool=True, check_origin: bool=True, idna_codec: Optional[dns.name.IDNACodec]=None, allow_directives: Union[bool, Iterable[str]]=True) -> Zone:
    """Read a zone file and build a zone object.

    *f*, a file or ``str``.  If *f* is a string, it is treated
    as the name of a file to open.

    *origin*, a ``dns.name.Name``, a ``str``, or ``None``.  The origin
    of the zone; if not specified, the first ``$ORIGIN`` statement in the
    zone file will determine the origin of the zone.

    *rdclass*, an ``int``, the zone's rdata class; the default is class IN.

    *relativize*, a ``bool``, determine's whether domain names are
    relativized to the zone's origin.  The default is ``True``.

    *zone_factory*, the zone factory to use or ``None``.  If ``None``, then
    ``dns.zone.Zone`` will be used.  The value may be any class or callable
    that returns a subclass of ``dns.zone.Zone``.

    *filename*, a ``str`` or ``None``, the filename to emit when
    describing where an error occurred; the default is ``'<string>'``.

    *allow_include*, a ``bool``.  If ``True``, the default, then ``$INCLUDE``
    directives are permitted.  If ``False``, then encoutering a ``$INCLUDE``
    will raise a ``SyntaxError`` exception.

    *check_origin*, a ``bool``.  If ``True``, the default, then sanity
    checks of the origin node will be made by calling the zone's
    ``check_origin()`` method.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    *allow_directives*, a ``bool`` or an iterable of `str`.  If ``True``, the default,
    then directives are permitted, and the *allow_include* parameter controls whether
    ``$INCLUDE`` is permitted.  If ``False`` or an empty iterable, then no directive
    processing is done and any directive-like text will be treated as a regular owner
    name.  If a non-empty iterable, then only the listed directives (including the
    ``$``) are allowed.

    Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

    Raises ``dns.zone.NoNS`` if there is no NS RRset.

    Raises ``KeyError`` if there is no origin node.

    Returns a subclass of ``dns.zone.Zone``.
    """
    pass

def from_xfr(xfr: Any, zone_factory: Any=Zone, relativize: bool=True, check_origin: bool=True) -> Zone:
    """Convert the output of a zone transfer generator into a zone object.

    *xfr*, a generator of ``dns.message.Message`` objects, typically
    ``dns.query.xfr()``.

    *relativize*, a ``bool``, determine's whether domain names are
    relativized to the zone's origin.  The default is ``True``.
    It is essential that the relativize setting matches the one specified
    to the generator.

    *check_origin*, a ``bool``.  If ``True``, the default, then sanity
    checks of the origin node will be made by calling the zone's
    ``check_origin()`` method.

    Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

    Raises ``dns.zone.NoNS`` if there is no NS RRset.

    Raises ``KeyError`` if there is no origin node.

    Raises ``ValueError`` if no messages are yielded by the generator.

    Returns a subclass of ``dns.zone.Zone``.
    """
    pass
