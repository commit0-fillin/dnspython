import collections
from typing import Any, Callable, Iterator, List, Optional, Tuple, Union
import dns.exception
import dns.name
import dns.node
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.serial
import dns.ttl

class TransactionManager:

    def reader(self) -> 'Transaction':
        """Begin a read-only transaction."""
        return Transaction(self, read_only=True)

    def writer(self, replacement: bool=False) -> 'Transaction':
        """Begin a writable transaction.

        *replacement*, a ``bool``.  If `True`, the content of the
        transaction completely replaces any prior content.  If False,
        the default, then the content of the transaction updates the
        existing content.
        """
        return Transaction(self, replacement=replacement)

    def origin_information(self) -> Tuple[Optional[dns.name.Name], bool, Optional[dns.name.Name]]:
        """Returns a tuple

            (absolute_origin, relativize, effective_origin)

        giving the absolute name of the default origin for any
        relative domain names, the "effective origin", and whether
        names should be relativized.  The "effective origin" is the
        absolute origin if relativize is False, and the empty name if
        relativize is true.  (The effective origin is provided even
        though it can be computed from the absolute_origin and
        relativize setting because it avoids a lot of code
        duplication.)

        If the returned names are `None`, then no origin information is
        available.

        This information is used by code working with transactions to
        allow it to coordinate relativization.  The transaction code
        itself takes what it gets (i.e. does not change name
        relativity).

        """
        absolute_origin = self.get_origin()
        relativize = self.relativize
        effective_origin = absolute_origin if not relativize else dns.name.empty

        return (absolute_origin, relativize, effective_origin)

    def get_class(self) -> dns.rdataclass.RdataClass:
        """The class of the transaction manager."""
        return self.rdclass

    def from_wire_origin(self) -> Optional[dns.name.Name]:
        """Origin to use in from_wire() calls."""
        return self.get_origin()

class DeleteNotExact(dns.exception.DNSException):
    """Existing data did not match data specified by an exact delete."""

class ReadOnly(dns.exception.DNSException):
    """Tried to write to a read-only transaction."""

class AlreadyEnded(dns.exception.DNSException):
    """Tried to use an already-ended transaction."""
CheckPutRdatasetType = Callable[['Transaction', dns.name.Name, dns.rdataset.Rdataset], None]
CheckDeleteRdatasetType = Callable[['Transaction', dns.name.Name, dns.rdatatype.RdataType, dns.rdatatype.RdataType], None]
CheckDeleteNameType = Callable[['Transaction', dns.name.Name], None]

class Transaction:

    def __init__(self, manager: TransactionManager, replacement: bool=False, read_only: bool=False):
        self.manager = manager
        self.replacement = replacement
        self.read_only = read_only
        self._ended = False
        self._check_put_rdataset: List[CheckPutRdatasetType] = []
        self._check_delete_rdataset: List[CheckDeleteRdatasetType] = []
        self._check_delete_name: List[CheckDeleteNameType] = []

    def get(self, name: Optional[Union[dns.name.Name, str]], rdtype: Union[dns.rdatatype.RdataType, str], covers: Union[dns.rdatatype.RdataType, str]=dns.rdatatype.NONE) -> dns.rdataset.Rdataset:
        """Return the rdataset associated with *name*, *rdtype*, and *covers*,
        or `None` if not found.

        Note that the returned rdataset is immutable.
        """
        pass

    def get_node(self, name: dns.name.Name) -> Optional[dns.node.Node]:
        """Return the node at *name*, if any.

        Returns an immutable node or ``None``.
        """
        pass

    def add(self, *args: Any) -> None:
        """Add records.

        The arguments may be:

            - rrset

            - name, rdataset...

            - name, ttl, rdata...
        """
        pass

    def replace(self, *args: Any) -> None:
        """Replace the existing rdataset at the name with the specified
        rdataset, or add the specified rdataset if there was no existing
        rdataset.

        The arguments may be:

            - rrset

            - name, rdataset...

            - name, ttl, rdata...

        Note that if you want to replace the entire node, you should do
        a delete of the name followed by one or more calls to add() or
        replace().
        """
        pass

    def delete(self, *args: Any) -> None:
        """Delete records.

        It is not an error if some of the records are not in the existing
        set.

        The arguments may be:

            - rrset

            - name

            - name, rdatatype, [covers]

            - name, rdataset...

            - name, rdata...
        """
        pass

    def delete_exact(self, *args: Any) -> None:
        """Delete records.

        The arguments may be:

            - rrset

            - name

            - name, rdatatype, [covers]

            - name, rdataset...

            - name, rdata...

        Raises dns.transaction.DeleteNotExact if some of the records
        are not in the existing set.

        """
        pass

    def name_exists(self, name: Union[dns.name.Name, str]) -> bool:
        """Does the specified name exist?"""
        pass

    def update_serial(self, value: int=1, relative: bool=True, name: dns.name.Name=dns.name.empty) -> None:
        """Update the serial number.

        *value*, an `int`, is an increment if *relative* is `True`, or the
        actual value to set if *relative* is `False`.

        Raises `KeyError` if there is no SOA rdataset at *name*.

        Raises `ValueError` if *value* is negative or if the increment is
        so large that it would cause the new serial to be less than the
        prior value.
        """
        pass

    def __iter__(self):
        self._check_ended()
        return self._iterate_rdatasets()

    def changed(self) -> bool:
        """Has this transaction changed anything?

        For read-only transactions, the result is always `False`.

        For writable transactions, the result is `True` if at some time
        during the life of the transaction, the content was changed.
        """
        pass

    def commit(self) -> None:
        """Commit the transaction.

        Normally transactions are used as context managers and commit
        or rollback automatically, but it may be done explicitly if needed.
        A ``dns.transaction.Ended`` exception will be raised if you try
        to use a transaction after it has been committed or rolled back.

        Raises an exception if the commit fails (in which case the transaction
        is also rolled back.
        """
        pass

    def rollback(self) -> None:
        """Rollback the transaction.

        Normally transactions are used as context managers and commit
        or rollback automatically, but it may be done explicitly if needed.
        A ``dns.transaction.AlreadyEnded`` exception will be raised if you try
        to use a transaction after it has been committed or rolled back.

        Rollback cannot otherwise fail.
        """
        pass

    def check_put_rdataset(self, check: CheckPutRdatasetType) -> None:
        """Call *check* before putting (storing) an rdataset.

        The function is called with the transaction, the name, and the rdataset.

        The check function may safely make non-mutating transaction method
        calls, but behavior is undefined if mutating transaction methods are
        called.  The check function should raise an exception if it objects to
        the put, and otherwise should return ``None``.
        """
        pass

    def check_delete_rdataset(self, check: CheckDeleteRdatasetType) -> None:
        """Call *check* before deleting an rdataset.

        The function is called with the transaction, the name, the rdatatype,
        and the covered rdatatype.

        The check function may safely make non-mutating transaction method
        calls, but behavior is undefined if mutating transaction methods are
        called.  The check function should raise an exception if it objects to
        the put, and otherwise should return ``None``.
        """
        pass

    def check_delete_name(self, check: CheckDeleteNameType) -> None:
        """Call *check* before putting (storing) an rdataset.

        The function is called with the transaction and the name.

        The check function may safely make non-mutating transaction method
        calls, but behavior is undefined if mutating transaction methods are
        called.  The check function should raise an exception if it objects to
        the put, and otherwise should return ``None``.
        """
        pass

    def iterate_rdatasets(self) -> Iterator[Tuple[dns.name.Name, dns.rdataset.Rdataset]]:
        """Iterate all the rdatasets in the transaction, returning
        (`dns.name.Name`, `dns.rdataset.Rdataset`) tuples.

        Note that as is usual with python iterators, adding or removing items
        while iterating will invalidate the iterator and may raise `RuntimeError`
        or fail to iterate over all entries."""
        pass

    def iterate_names(self) -> Iterator[dns.name.Name]:
        """Iterate all the names in the transaction.

        Note that as is usual with python iterators, adding or removing names
        while iterating will invalidate the iterator and may raise `RuntimeError`
        or fail to iterate over all entries."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._ended:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        return False

    def _get_rdataset(self, name, rdtype, covers):
        """Return the rdataset associated with *name*, *rdtype*, and *covers*,
        or `None` if not found.
        """
        pass

    def _put_rdataset(self, name, rdataset):
        """Store the rdataset."""
        pass

    def _delete_name(self, name):
        """Delete all data associated with *name*.

        It is not an error if the name does not exist.
        """
        pass

    def _delete_rdataset(self, name, rdtype, covers):
        """Delete all data associated with *name*, *rdtype*, and *covers*.

        It is not an error if the rdataset does not exist.
        """
        pass

    def _name_exists(self, name):
        """Does name exist?

        Returns a bool.
        """
        pass

    def _changed(self):
        """Has this transaction changed anything?"""
        pass

    def _end_transaction(self, commit):
        """End the transaction.

        *commit*, a bool.  If ``True``, commit the transaction, otherwise
        roll it back.

        If committing and the commit fails, then roll back and raise an
        exception.
        """
        pass

    def _set_origin(self, origin):
        """Set the origin.

        This method is called when reading a possibly relativized
        source, and an origin setting operation occurs (e.g. $ORIGIN
        in a zone file).
        """
        pass

    def _iterate_rdatasets(self):
        """Return an iterator that yields (name, rdataset) tuples."""
        pass

    def _iterate_names(self):
        """Return an iterator that yields a name."""
        pass

    def _get_node(self, name):
        """Return the node at *name*, if any.

        Returns a node or ``None``.
        """
        pass
