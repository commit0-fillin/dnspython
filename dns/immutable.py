import collections.abc
from typing import Any, Callable
from dns._immutable_ctx import immutable

@immutable
class Dict(collections.abc.Mapping):

    def __init__(self, dictionary: Any, no_copy: bool=False, map_factory: Callable[[], collections.abc.MutableMapping]=dict):
        """Make an immutable dictionary from the specified dictionary.

        If *no_copy* is `True`, then *dictionary* will be wrapped instead
        of copied.  Only set this if you are sure there will be no external
        references to the dictionary.
        """
        if no_copy and isinstance(dictionary, collections.abc.MutableMapping):
            self._odict = dictionary
        else:
            self._odict = map_factory()
            self._odict.update(dictionary)
        self._hash = None

    def __getitem__(self, key):
        return self._odict.__getitem__(key)

    def __hash__(self):
        if self._hash is None:
            h = 0
            for key in sorted(self._odict.keys()):
                h ^= hash(key)
            object.__setattr__(self, '_hash', h)
        return self._hash

    def __len__(self):
        return len(self._odict)

    def __iter__(self):
        return iter(self._odict)

def constify(o: Any) -> Any:
    """
    Convert mutable types to immutable types.
    """
    if isinstance(o, list):
        return tuple(constify(item) for item in o)
    elif isinstance(o, dict):
        return Dict({constify(k): constify(v) for k, v in o.items()})
    elif isinstance(o, set):
        return frozenset(constify(item) for item in o)
    elif isinstance(o, (str, int, float, bool, tuple, frozenset)) or o is None:
        return o
    else:
        # For other types, we return them as-is
        # You might want to add more specific handling for other mutable types
        return o
