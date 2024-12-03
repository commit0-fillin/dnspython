"""DNS GENERATE range conversion."""
from typing import Tuple
import dns

def from_text(text: str) -> Tuple[int, int, int]:
    """Convert the text form of a range in a ``$GENERATE`` statement to an
    integer.

    *text*, a ``str``, the textual range in ``$GENERATE`` form.

    Returns a tuple of three ``int`` values ``(start, stop, step)``.
    """
    parts = text.split('/')
    if len(parts) == 1:
        range_part = parts[0]
        step = 1
    elif len(parts) == 2:
        range_part, step = parts
        step = int(step)
    else:
        raise dns.exception.SyntaxError("invalid range")

    range_values = range_part.split('-')
    if len(range_values) == 2:
        start, stop = map(int, range_values)
    else:
        raise dns.exception.SyntaxError("invalid range")

    if start > stop:
        raise dns.exception.SyntaxError("start must be <= stop")
    if step <= 0:
        raise dns.exception.SyntaxError("step must be positive")

    return (start, stop, step)
