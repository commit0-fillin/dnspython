import itertools

class Set:
    """A simple set class.

    This class was originally used to deal with sets being missing in
    ancient versions of python, but dnspython will continue to use it
    as these sets are based on lists and are thus indexable, and this
    ability is widely used in dnspython applications.
    """
    __slots__ = ['items']

    def __init__(self, items=None):
        """Initialize the set.

        *items*, an iterable or ``None``, the initial set of items.
        """
        self.items = dict()
        if items is not None:
            for item in items:
                self.add(item)

    def __repr__(self):
        return 'dns.set.Set(%s)' % repr(list(self.items.keys()))

    def add(self, item):
        """Add an item to the set."""
        self.items[item] = None

    def remove(self, item):
        """Remove an item from the set."""
        del self.items[item]

    def discard(self, item):
        """Remove an item from the set if present."""
        self.items.pop(item, None)

    def pop(self):
        """Remove an arbitrary item from the set."""
        if not self.items:
            raise KeyError("pop from an empty set")
        return self.items.popitem()[0]

    def _clone(self) -> 'Set':
        """Make a (shallow) copy of the set.

        There is a 'clone protocol' that subclasses of this class
        should use.  To make a copy, first call your super's _clone()
        method, and use the object returned as the new instance.  Then
        make shallow copies of the attributes defined in the subclass.

        This protocol allows us to write the set algorithms that
        return new instances (e.g. union) once, and keep using them in
        subclasses.
        """
        clone = Set()
        clone.items = self.items.copy()
        return clone

    def __copy__(self):
        """Make a (shallow) copy of the set."""
        return self._clone()

    def copy(self):
        """Make a (shallow) copy of the set."""
        return self._clone()

    def union_update(self, other):
        """Update the set, adding any elements from other which are not
        already in the set.
        """
        for item in other:
            self.add(item)

    def intersection_update(self, other):
        """Update the set, removing any elements from other which are not
        in both sets.
        """
        self.items = {item: None for item in self.items if item in other}

    def difference_update(self, other):
        """Update the set, removing any elements from other which are in
        the set.
        """
        for item in other:
            self.discard(item)

    def symmetric_difference_update(self, other):
        """Update the set, retaining only elements unique to both sets."""
        for item in other:
            if item in self.items:
                del self.items[item]
            else:
                self.items[item] = None

    def union(self, other):
        """Return a new set which is the union of ``self`` and ``other``.

        Returns the same Set type as this set.
        """
        new_set = self._clone()
        new_set.union_update(other)
        return new_set

    def intersection(self, other):
        """Return a new set which is the intersection of ``self`` and
        ``other``.

        Returns the same Set type as this set.
        """
        new_set = self._clone()
        new_set.intersection_update(other)
        return new_set

    def difference(self, other):
        """Return a new set which ``self`` - ``other``, i.e. the items
        in ``self`` which are not also in ``other``.

        Returns the same Set type as this set.
        """
        new_set = self._clone()
        new_set.difference_update(other)
        return new_set

    def symmetric_difference(self, other):
        """Return a new set which (``self`` - ``other``) | (``other``
        - ``self), ie: the items in either ``self`` or ``other`` which
        are not contained in their intersection.

        Returns the same Set type as this set.
        """
        new_set = self._clone()
        new_set.symmetric_difference_update(other)
        return new_set

    def __or__(self, other):
        return self.union(other)

    def __and__(self, other):
        return self.intersection(other)

    def __add__(self, other):
        return self.union(other)

    def __sub__(self, other):
        return self.difference(other)

    def __xor__(self, other):
        return self.symmetric_difference(other)

    def __ior__(self, other):
        self.union_update(other)
        return self

    def __iand__(self, other):
        self.intersection_update(other)
        return self

    def __iadd__(self, other):
        self.union_update(other)
        return self

    def __isub__(self, other):
        self.difference_update(other)
        return self

    def __ixor__(self, other):
        self.symmetric_difference_update(other)
        return self

    def update(self, other):
        """Update the set, adding any elements from other which are not
        already in the set.

        *other*, the collection of items with which to update the set, which
        may be any iterable type.
        """
        for item in other:
            self.add(item)

    def clear(self):
        """Make the set empty."""
        self.items.clear()

    def __eq__(self, other):
        return self.items == other.items

    def __ne__(self, other):
        return not self.__eq__(other)

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __getitem__(self, i):
        if isinstance(i, slice):
            return list(itertools.islice(self.items, i.start, i.stop, i.step))
        else:
            return next(itertools.islice(self.items, i, i + 1))

    def __delitem__(self, i):
        if isinstance(i, slice):
            for elt in list(self[i]):
                del self.items[elt]
        else:
            del self.items[self[i]]

    def issubset(self, other):
        """Is this set a subset of *other*?

        Returns a ``bool``.
        """
        return all(item in other for item in self.items)

    def issuperset(self, other):
        """Is this set a superset of *other*?

        Returns a ``bool``.
        """
        return all(item in self.items for item in other)
