"""DNS Versioned Zones."""
import collections
import threading
from typing import Callable, Deque, Optional, Set, Union
import dns.exception
import dns.immutable
import dns.name
import dns.node
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.zone

class UseTransaction(dns.exception.DNSException):
    """To alter a versioned zone, use a transaction."""
Node = dns.zone.VersionedNode
ImmutableNode = dns.zone.ImmutableVersionedNode
Version = dns.zone.Version
WritableVersion = dns.zone.WritableVersion
ImmutableVersion = dns.zone.ImmutableVersion
Transaction = dns.zone.Transaction

class Zone(dns.zone.Zone):
    __slots__ = ['_versions', '_versions_lock', '_write_txn', '_write_waiters', '_write_event', '_pruning_policy', '_readers']
    node_factory = Node

    def __init__(self, origin: Optional[Union[dns.name.Name, str]], rdclass: dns.rdataclass.RdataClass=dns.rdataclass.IN, relativize: bool=True, pruning_policy: Optional[Callable[['Zone', Version], Optional[bool]]]=None):
        """Initialize a versioned zone object.

        *origin* is the origin of the zone.  It may be a ``dns.name.Name``,
        a ``str``, or ``None``.  If ``None``, then the zone's origin will
        be set by the first ``$ORIGIN`` line in a zone file.

        *rdclass*, an ``int``, the zone's rdata class; the default is class IN.

        *relativize*, a ``bool``, determine's whether domain names are
        relativized to the zone's origin.  The default is ``True``.

        *pruning policy*, a function taking a ``Zone`` and a ``Version`` and returning
        a ``bool``, or ``None``.  Should the version be pruned?  If ``None``,
        the default policy, which retains one version is used.
        """
        super().__init__(origin, rdclass, relativize)
        self._versions: Deque[Version] = collections.deque()
        self._version_lock = threading.Lock()
        if pruning_policy is None:
            self._pruning_policy = self._default_pruning_policy
        else:
            self._pruning_policy = pruning_policy
        self._write_txn: Optional[Transaction] = None
        self._write_event: Optional[threading.Event] = None
        self._write_waiters: Deque[threading.Event] = collections.deque()
        self._readers: Set[Transaction] = set()
        self._commit_version_unlocked(None, WritableVersion(self, replacement=True), origin)

    def set_max_versions(self, max_versions: Optional[int]) -> None:
        """Set a pruning policy that retains up to the specified number
        of versions
        """
        if max_versions is None:
            self.set_pruning_policy(None)
        else:
            def policy(zone: 'Zone', version: Version) -> Optional[bool]:
                return len(zone._versions) > max_versions
            self.set_pruning_policy(policy)

    def set_pruning_policy(self, policy: Optional[Callable[['Zone', Version], Optional[bool]]]) -> None:
        """Set the pruning policy for the zone.

        The *policy* function takes a `Version` and returns `True` if
        the version should be pruned, and `False` otherwise.  `None`
        may also be specified for policy, in which case the default policy
        is used.

        Pruning checking proceeds from the least version and the first
        time the function returns `False`, the checking stops.  I.e. the
        retained versions are always a consecutive sequence.
        """
        if policy is None:
            self._pruning_policy = self._default_pruning_policy
        else:
            self._pruning_policy = policy
