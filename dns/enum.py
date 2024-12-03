import enum
from typing import Type, TypeVar, Union
TIntEnum = TypeVar('TIntEnum', bound='IntEnum')

class IntEnum(enum.IntEnum):

    @classmethod
    def make(cls: Type[TIntEnum], value: Union[int, str]) -> TIntEnum:
        """Convert text or a value into an enumerated type, if possible.

        *value*, the ``int`` or ``str`` to convert.

        Raises a class-specific exception if a ``str`` is provided that
        cannot be converted.

        Raises ``ValueError`` if the value is out of range.

        Returns an enumeration from the calling class corresponding to the
        value, if one is defined, or an ``int`` otherwise.
        """
        if isinstance(value, str):
            try:
                return cls[value.upper()]
            except KeyError:
                raise ValueError(f"'{value}' is not a valid {cls.__name__}")
        elif isinstance(value, int):
            try:
                return cls(value)
            except ValueError:
                # If the int value doesn't correspond to any enum member,
                # we return it as is (as per the method description)
                return value
        else:
            raise TypeError(f"Expected str or int, not {type(value).__name__}")
