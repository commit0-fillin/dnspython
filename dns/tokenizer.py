"""Tokenize DNS zone file format"""
import io
import sys
from typing import Any, List, Optional, Tuple
import dns.exception
import dns.name
import dns.ttl
_DELIMITERS = {' ', '\t', '\n', ';', '(', ')', '"'}
_QUOTING_DELIMITERS = {'"'}
EOF = 0
EOL = 1
WHITESPACE = 2
IDENTIFIER = 3
QUOTED_STRING = 4
COMMENT = 5
DELIMITER = 6

class UngetBufferFull(dns.exception.DNSException):
    """An attempt was made to unget a token when the unget buffer was full."""

class Token:
    """A DNS zone file format token.

    ttype: The token type
    value: The token value
    has_escape: Does the token value contain escapes?
    """

    def __init__(self, ttype: int, value: Any='', has_escape: bool=False, comment: Optional[str]=None):
        """Initialize a token instance."""
        self.ttype = ttype
        self.value = value
        self.has_escape = has_escape
        self.comment = comment

    def __eq__(self, other):
        if not isinstance(other, Token):
            return False
        return self.ttype == other.ttype and self.value == other.value

    def __ne__(self, other):
        if not isinstance(other, Token):
            return True
        return self.ttype != other.ttype or self.value != other.value

    def __str__(self):
        return '%d "%s"' % (self.ttype, self.value)

class Tokenizer:
    """A DNS zone file format tokenizer.

    A token object is basically a (type, value) tuple.  The valid
    types are EOF, EOL, WHITESPACE, IDENTIFIER, QUOTED_STRING,
    COMMENT, and DELIMITER.

    file: The file to tokenize

    ungotten_char: The most recently ungotten character, or None.

    ungotten_token: The most recently ungotten token, or None.

    multiline: The current multiline level.  This value is increased
    by one every time a '(' delimiter is read, and decreased by one every time
    a ')' delimiter is read.

    quoting: This variable is true if the tokenizer is currently
    reading a quoted string.

    eof: This variable is true if the tokenizer has encountered EOF.

    delimiters: The current delimiter dictionary.

    line_number: The current line number

    filename: A filename that will be returned by the where() method.

    idna_codec: A dns.name.IDNACodec, specifies the IDNA
    encoder/decoder.  If None, the default IDNA 2003
    encoder/decoder is used.
    """

    def __init__(self, f: Any=sys.stdin, filename: Optional[str]=None, idna_codec: Optional[dns.name.IDNACodec]=None):
        """Initialize a tokenizer instance.

        f: The file to tokenize.  The default is sys.stdin.
        This parameter may also be a string, in which case the tokenizer
        will take its input from the contents of the string.

        filename: the name of the filename that the where() method
        will return.

        idna_codec: A dns.name.IDNACodec, specifies the IDNA
        encoder/decoder.  If None, the default IDNA 2003
        encoder/decoder is used.
        """
        if isinstance(f, str):
            f = io.StringIO(f)
            if filename is None:
                filename = '<string>'
        elif isinstance(f, bytes):
            f = io.StringIO(f.decode())
            if filename is None:
                filename = '<string>'
        elif filename is None:
            if f is sys.stdin:
                filename = '<stdin>'
            else:
                filename = '<file>'
        self.file = f
        self.ungotten_char: Optional[str] = None
        self.ungotten_token: Optional[Token] = None
        self.multiline = 0
        self.quoting = False
        self.eof = False
        self.delimiters = _DELIMITERS
        self.line_number = 1
        assert filename is not None
        self.filename = filename
        if idna_codec is None:
            self.idna_codec: dns.name.IDNACodec = dns.name.IDNA_2003
        else:
            self.idna_codec = idna_codec

    def _get_char(self) -> str:
        """Read a character from input."""
        if self.ungotten_char is not None:
            c = self.ungotten_char
            self.ungotten_char = None
        else:
            c = self.file.read(1)
            if c == '\n':
                self.line_number += 1
        if c == '' and self.multiline:
            raise dns.exception.SyntaxError("unbalanced parentheses")
        return c

    def where(self) -> Tuple[str, int]:
        """Return the current location in the input.

        Returns a (string, int) tuple.  The first item is the filename of
        the input, the second is the current line number.
        """
        return (self.filename, self.line_number)

    def _unget_char(self, c: str) -> None:
        """Unget a character.

        The unget buffer for characters is only one character large; it is
        an error to try to unget a character when the unget buffer is not
        empty.

        c: the character to unget
        raises UngetBufferFull: there is already an ungotten char
        """
        if self.ungotten_char is not None:
            raise UngetBufferFull
        self.ungotten_char = c
        if c == '\n':
            self.line_number -= 1

    def skip_whitespace(self) -> int:
        """Consume input until a non-whitespace character is encountered.

        The non-whitespace character is then ungotten, and the number of
        whitespace characters consumed is returned.

        If the tokenizer is in multiline mode, then newlines are whitespace.

        Returns the number of characters skipped.
        """
        skipped = 0
        while True:
            c = self._get_char()
            if c == '' or c not in (' ', '\t', '\r', '\n'):
                if c != '':
                    self._unget_char(c)
                return skipped
            if c == '\n' and not self.multiline:
                self._unget_char(c)
                return skipped
            skipped += 1

    def get(self, want_leading: bool=False, want_comment: bool=False) -> Token:
        """Get the next token.

        want_leading: If True, return a WHITESPACE token if the
        first character read is whitespace.  The default is False.

        want_comment: If True, return a COMMENT token if the
        first token read is a comment.  The default is False.

        Raises dns.exception.UnexpectedEnd: input ended prematurely

        Raises dns.exception.SyntaxError: input was badly formed

        Returns a Token.
        """
        pass

    def unget(self, token: Token) -> None:
        """Unget a token.

        The unget buffer for tokens is only one token large; it is
        an error to try to unget a token when the unget buffer is not
        empty.

        token: the token to unget

        Raises UngetBufferFull: there is already an ungotten token
        """
        pass

    def next(self):
        """Return the next item in an iteration.

        Returns a Token.
        """
        pass
    __next__ = next

    def __iter__(self):
        return self

    def get_int(self, base: int=10) -> int:
        """Read the next token and interpret it as an unsigned integer.

        Raises dns.exception.SyntaxError if not an unsigned integer.

        Returns an int.
        """
        pass

    def get_uint8(self) -> int:
        """Read the next token and interpret it as an 8-bit unsigned
        integer.

        Raises dns.exception.SyntaxError if not an 8-bit unsigned integer.

        Returns an int.
        """
        pass

    def get_uint16(self, base: int=10) -> int:
        """Read the next token and interpret it as a 16-bit unsigned
        integer.

        Raises dns.exception.SyntaxError if not a 16-bit unsigned integer.

        Returns an int.
        """
        pass

    def get_uint32(self, base: int=10) -> int:
        """Read the next token and interpret it as a 32-bit unsigned
        integer.

        Raises dns.exception.SyntaxError if not a 32-bit unsigned integer.

        Returns an int.
        """
        pass

    def get_uint48(self, base: int=10) -> int:
        """Read the next token and interpret it as a 48-bit unsigned
        integer.

        Raises dns.exception.SyntaxError if not a 48-bit unsigned integer.

        Returns an int.
        """
        pass

    def get_string(self, max_length: Optional[int]=None) -> str:
        """Read the next token and interpret it as a string.

        Raises dns.exception.SyntaxError if not a string.
        Raises dns.exception.SyntaxError if token value length
        exceeds max_length (if specified).

        Returns a string.
        """
        pass

    def get_identifier(self) -> str:
        """Read the next token, which should be an identifier.

        Raises dns.exception.SyntaxError if not an identifier.

        Returns a string.
        """
        pass

    def get_remaining(self, max_tokens: Optional[int]=None) -> List[Token]:
        """Return the remaining tokens on the line, until an EOL or EOF is seen.

        max_tokens: If not None, stop after this number of tokens.

        Returns a list of tokens.
        """
        pass

    def concatenate_remaining_identifiers(self, allow_empty: bool=False) -> str:
        """Read the remaining tokens on the line, which should be identifiers.

        Raises dns.exception.SyntaxError if there are no remaining tokens,
        unless `allow_empty=True` is given.

        Raises dns.exception.SyntaxError if a token is seen that is not an
        identifier.

        Returns a string containing a concatenation of the remaining
        identifiers.
        """
        pass

    def as_name(self, token: Token, origin: Optional[dns.name.Name]=None, relativize: bool=False, relativize_to: Optional[dns.name.Name]=None) -> dns.name.Name:
        """Try to interpret the token as a DNS name.

        Raises dns.exception.SyntaxError if not a name.

        Returns a dns.name.Name.
        """
        pass

    def get_name(self, origin: Optional[dns.name.Name]=None, relativize: bool=False, relativize_to: Optional[dns.name.Name]=None) -> dns.name.Name:
        """Read the next token and interpret it as a DNS name.

        Raises dns.exception.SyntaxError if not a name.

        Returns a dns.name.Name.
        """
        pass

    def get_eol_as_token(self) -> Token:
        """Read the next token and raise an exception if it isn't EOL or
        EOF.

        Returns a string.
        """
        pass

    def get_ttl(self) -> int:
        """Read the next token and interpret it as a DNS TTL.

        Raises dns.exception.SyntaxError or dns.ttl.BadTTL if not an
        identifier or badly formed.

        Returns an int.
        """
        pass
