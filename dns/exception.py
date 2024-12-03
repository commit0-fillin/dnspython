"""Common DNS Exceptions.

Dnspython modules may also define their own exceptions, which will
always be subclasses of ``DNSException``.
"""
from typing import Optional, Set

class DNSException(Exception):
    """Abstract base class shared by all dnspython exceptions.

    It supports two basic modes of operation:

    a) Old/compatible mode is used if ``__init__`` was called with
    empty *kwargs*.  In compatible mode all *args* are passed
    to the standard Python Exception class as before and all *args* are
    printed by the standard ``__str__`` implementation.  Class variable
    ``msg`` (or doc string if ``msg`` is ``None``) is returned from ``str()``
    if *args* is empty.

    b) New/parametrized mode is used if ``__init__`` was called with
    non-empty *kwargs*.
    In the new mode *args* must be empty and all kwargs must match
    those set in class variable ``supp_kwargs``. All kwargs are stored inside
    ``self.kwargs`` and used in a new ``__str__`` implementation to construct
    a formatted message based on the ``fmt`` class variable, a ``string``.

    In the simplest case it is enough to override the ``supp_kwargs``
    and ``fmt`` class variables to get nice parametrized messages.
    """
    msg: Optional[str] = None
    supp_kwargs: Set[str] = set()
    fmt: Optional[str] = None

    def __init__(self, *args, **kwargs):
        self._check_params(*args, **kwargs)
        if kwargs:
            self.kwargs = self._check_kwargs(**kwargs)
            self.msg = str(self)
        else:
            self.kwargs = dict()
        if self.msg is None:
            self.msg = self.__doc__
        if args:
            super().__init__(*args)
        else:
            super().__init__(self.msg)

    def _check_params(self, *args, **kwargs):
        """Old exceptions supported only args and not kwargs.

        For sanity we do not allow to mix old and new behavior."""
        if args and kwargs:
            raise TypeError("Cannot mix args and kwargs in DNSException")

    def _fmt_kwargs(self, **kwargs):
        """Format kwargs before printing them.

        Resulting dictionary has to have keys necessary for str.format call
        on fmt class variable.
        """
        return {k: repr(v) for k, v in kwargs.items()}

    def __str__(self):
        if self.kwargs and self.fmt:
            fmtargs = self._fmt_kwargs(**self.kwargs)
            return self.fmt.format(**fmtargs)
        else:
            return super().__str__()

class FormError(DNSException):
    """DNS message is malformed."""

class SyntaxError(DNSException):
    """Text input is malformed."""

class UnexpectedEnd(SyntaxError):
    """Text input ended unexpectedly."""

class TooBig(DNSException):
    """The DNS message is too big."""

class Timeout(DNSException):
    """The DNS operation timed out."""
    supp_kwargs = {'timeout'}
    fmt = 'The DNS operation timed out after {timeout:.3f} seconds'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class UnsupportedAlgorithm(DNSException):
    """The DNSSEC algorithm is not supported."""

class AlgorithmKeyMismatch(UnsupportedAlgorithm):
    """The DNSSEC algorithm is not supported for the given key type."""

class ValidationFailure(DNSException):
    """The DNSSEC signature is invalid."""

class DeniedByPolicy(DNSException):
    """Denied by DNSSEC policy."""

class ExceptionWrapper:

    def __init__(self, exception_class):
        self.exception_class = exception_class

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None and (not isinstance(exc_val, self.exception_class)):
            raise self.exception_class(str(exc_val)) from exc_val
        return False
