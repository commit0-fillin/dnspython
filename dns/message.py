"""DNS Messages"""
import contextlib
import io
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import dns.edns
import dns.entropy
import dns.enum
import dns.exception
import dns.flags
import dns.name
import dns.opcode
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.OPT
import dns.rdtypes.ANY.TSIG
import dns.renderer
import dns.rrset
import dns.tsig
import dns.ttl
import dns.wire

class ShortHeader(dns.exception.FormError):
    """The DNS packet passed to from_wire() is too short."""

class TrailingJunk(dns.exception.FormError):
    """The DNS packet passed to from_wire() has extra junk at the end of it."""

class UnknownHeaderField(dns.exception.DNSException):
    """The header field name was not recognized when converting from text
    into a message."""

class BadEDNS(dns.exception.FormError):
    """An OPT record occurred somewhere other than
    the additional data section."""

class BadTSIG(dns.exception.FormError):
    """A TSIG record occurred somewhere other than the end of
    the additional data section."""

class UnknownTSIGKey(dns.exception.DNSException):
    """A TSIG with an unknown key was received."""

class Truncated(dns.exception.DNSException):
    """The truncated flag is set."""
    supp_kwargs = {'message'}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def message(self):
        """As much of the message as could be processed.

        Returns a ``dns.message.Message``.
        """
        return self._message

class NotQueryResponse(dns.exception.DNSException):
    """Message is not a response to a query."""

class ChainTooLong(dns.exception.DNSException):
    """The CNAME chain is too long."""

class AnswerForNXDOMAIN(dns.exception.DNSException):
    """The rcode is NXDOMAIN but an answer was found."""

class NoPreviousName(dns.exception.SyntaxError):
    """No previous name was known."""

class MessageSection(dns.enum.IntEnum):
    """Message sections"""
    QUESTION = 0
    ANSWER = 1
    AUTHORITY = 2
    ADDITIONAL = 3

class MessageError:

    def __init__(self, exception: Exception, offset: int):
        self.exception = exception
        self.offset = offset
DEFAULT_EDNS_PAYLOAD = 1232
MAX_CHAIN = 16
IndexKeyType = Tuple[int, dns.name.Name, dns.rdataclass.RdataClass, dns.rdatatype.RdataType, Optional[dns.rdatatype.RdataType], Optional[dns.rdataclass.RdataClass]]
IndexType = Dict[IndexKeyType, dns.rrset.RRset]
SectionType = Union[int, str, List[dns.rrset.RRset]]

class Message:
    """A DNS message."""
    _section_enum = MessageSection

    def __init__(self, id: Optional[int]=None):
        if id is None:
            self.id = dns.entropy.random_16()
        else:
            self.id = id
        self.flags = 0
        self.sections: List[List[dns.rrset.RRset]] = [[], [], [], []]
        self.opt: Optional[dns.rrset.RRset] = None
        self.request_payload = 0
        self.pad = 0
        self.keyring: Any = None
        self.tsig: Optional[dns.rrset.RRset] = None
        self.request_mac = b''
        self.xfr = False
        self.origin: Optional[dns.name.Name] = None
        self.tsig_ctx: Optional[Any] = None
        self.index: IndexType = {}
        self.errors: List[MessageError] = []
        self.time = 0.0

    @property
    def question(self) -> List[dns.rrset.RRset]:
        """The question section."""
        return self.sections[0]

    @property
    def answer(self) -> List[dns.rrset.RRset]:
        """The answer section."""
        return self.sections[1]

    @property
    def authority(self) -> List[dns.rrset.RRset]:
        """The authority section."""
        return self.sections[2]

    @property
    def additional(self) -> List[dns.rrset.RRset]:
        """The additional data section."""
        return self.sections[3]

    def __repr__(self):
        return '<DNS message, ID ' + repr(self.id) + '>'

    def __str__(self):
        return self.to_text()

    def to_text(self, origin: Optional[dns.name.Name]=None, relativize: bool=True, **kw: Dict[str, Any]) -> str:
        """Convert the message to text.

        The *origin*, *relativize*, and any other keyword
        arguments are passed to the RRset ``to_wire()`` method.

        Returns a ``str``.
        """
        s = io.StringIO()
        s.write(f'id {self.id}\n')
        s.write(f'opcode {dns.opcode.to_text(self.opcode())}\n')
        s.write(f'rcode {dns.rcode.to_text(self.rcode())}\n')
        s.write(f'flags {dns.flags.to_text(self.flags)}\n')
        if self.edns >= 0:
            s.write(f'edns {self.edns}\n')
            if self.ednsflags != 0:
                s.write(f'eflags {dns.flags.edns_to_text(self.ednsflags)}\n')
            s.write(f'payload {self.payload}\n')
        for (name, which) in self._section_enum.__members__.items():
            s.write(f';{name}\n')
            for rrset in self.section_from_number(which):
                s.write(rrset.to_text(origin, relativize, **kw))
                s.write('\n')
        return s.getvalue()

    def __eq__(self, other):
        """Two messages are equal if they have the same content in the
        header, question, answer, and authority sections.

        Returns a ``bool``.
        """
        if not isinstance(other, Message):
            return False
        if self.id != other.id:
            return False
        if self.flags != other.flags:
            return False
        for i, section in enumerate(self.sections):
            other_section = other.sections[i]
            for n in section:
                if n not in other_section:
                    return False
            for n in other_section:
                if n not in section:
                    return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def is_response(self, other: 'Message') -> bool:
        """Is *other*, also a ``dns.message.Message``, a response to this
        message?

        Returns a ``bool``.
        """
        return self.id == other.id and \
               dns.opcode.is_response(other.flags) and \
               not dns.opcode.is_response(self.flags)

    def section_number(self, section: List[dns.rrset.RRset]) -> int:
        """Return the "section number" of the specified section for use
        in indexing.

        *section* is one of the section attributes of this message.

        Raises ``ValueError`` if the section isn't known.

        Returns an ``int``.
        """
        for i, s in enumerate(self.sections):
            if section is s:
                return i
        raise ValueError('unknown section')

    def section_from_number(self, number: int) -> List[dns.rrset.RRset]:
        """Return the section list associated with the specified section
        number.

        *number* is a section number `int` or the text form of a section
        name.

        Raises ``ValueError`` if the section isn't known.

        Returns a ``list``.
        """
        if isinstance(number, str):
            section = self._section_enum[number.upper()]
            return self.sections[section]
        elif 0 <= number < len(self.sections):
            return self.sections[number]
        else:
            raise ValueError('invalid section')

    def find_rrset(self, section: SectionType, name: dns.name.Name, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, covers: dns.rdatatype.RdataType=dns.rdatatype.NONE, deleting: Optional[dns.rdataclass.RdataClass]=None, create: bool=False, force_unique: bool=False, idna_codec: Optional[dns.name.IDNACodec]=None) -> dns.rrset.RRset:
        """Find the RRset with the given attributes in the specified section.

        *section*, an ``int`` section number, a ``str`` section name, or one of
        the section attributes of this message.  This specifies the
        the section of the message to search.  For example::

            my_message.find_rrset(my_message.answer, name, rdclass, rdtype)
            my_message.find_rrset(dns.message.ANSWER, name, rdclass, rdtype)
            my_message.find_rrset("ANSWER", name, rdclass, rdtype)

        *name*, a ``dns.name.Name`` or ``str``, the name of the RRset.

        *rdclass*, an ``int`` or ``str``, the class of the RRset.

        *rdtype*, an ``int`` or ``str``, the type of the RRset.

        *covers*, an ``int`` or ``str``, the covers value of the RRset.
        The default is ``dns.rdatatype.NONE``.

        *deleting*, an ``int``, ``str``, or ``None``, the deleting value of the
        RRset.  The default is ``None``.

        *create*, a ``bool``.  If ``True``, create the RRset if it is not found.
        The created RRset is appended to *section*.

        *force_unique*, a ``bool``.  If ``True`` and *create* is also ``True``,
        create a new RRset regardless of whether a matching RRset exists
        already.  The default is ``False``.  This is useful when creating
        DDNS Update messages, as order matters for them.

        *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
        encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
        is used.

        Raises ``KeyError`` if the RRset was not found and create was
        ``False``.

        Returns a ``dns.rrset.RRset object``.
        """
        section = self.section_from_number(section)
        name = dns.name.from_text(name, origin=self.origin, idna_codec=idna_codec)
        rdclass = dns.rdataclass.RdataClass.make(rdclass)
        rdtype = dns.rdatatype.RdataType.make(rdtype)
        covers = dns.rdatatype.RdataType.make(covers)
        if deleting is not None:
            deleting = dns.rdataclass.RdataClass.make(deleting)

        for rrset in section:
            if rrset.name == name and rrset.rdclass == rdclass and \
               rrset.rdtype == rdtype and rrset.covers == covers and \
               rrset.deleting == deleting:
                return rrset

        if create:
            rrset = dns.rrset.RRset(name, rdclass, rdtype, covers, deleting)
            section.append(rrset)
            return rrset

        raise KeyError

    def get_rrset(self, section: SectionType, name: dns.name.Name, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, covers: dns.rdatatype.RdataType=dns.rdatatype.NONE, deleting: Optional[dns.rdataclass.RdataClass]=None, create: bool=False, force_unique: bool=False, idna_codec: Optional[dns.name.IDNACodec]=None) -> Optional[dns.rrset.RRset]:
        """Get the RRset with the given attributes in the specified section.

        If the RRset is not found, None is returned.

        *section*, an ``int`` section number, a ``str`` section name, or one of
        the section attributes of this message.  This specifies the
        the section of the message to search.  For example::

            my_message.get_rrset(my_message.answer, name, rdclass, rdtype)
            my_message.get_rrset(dns.message.ANSWER, name, rdclass, rdtype)
            my_message.get_rrset("ANSWER", name, rdclass, rdtype)

        *name*, a ``dns.name.Name`` or ``str``, the name of the RRset.

        *rdclass*, an ``int`` or ``str``, the class of the RRset.

        *rdtype*, an ``int`` or ``str``, the type of the RRset.

        *covers*, an ``int`` or ``str``, the covers value of the RRset.
        The default is ``dns.rdatatype.NONE``.

        *deleting*, an ``int``, ``str``, or ``None``, the deleting value of the
        RRset.  The default is ``None``.

        *create*, a ``bool``.  If ``True``, create the RRset if it is not found.
        The created RRset is appended to *section*.

        *force_unique*, a ``bool``.  If ``True`` and *create* is also ``True``,
        create a new RRset regardless of whether a matching RRset exists
        already.  The default is ``False``.  This is useful when creating
        DDNS Update messages, as order matters for them.

        *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
        encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
        is used.

        Returns a ``dns.rrset.RRset object`` or ``None``.
        """
        try:
            return self.find_rrset(section, name, rdclass, rdtype, covers, deleting, create, force_unique, idna_codec)
        except KeyError:
            return None

    def section_count(self, section: SectionType) -> int:
        """Returns the number of records in the specified section.

        *section*, an ``int`` section number, a ``str`` section name, or one of
        the section attributes of this message.  This specifies the
        the section of the message to count.  For example::

            my_message.section_count(my_message.answer)
            my_message.section_count(dns.message.ANSWER)
            my_message.section_count("ANSWER")
        """
        return len(self.section_from_number(section))

    def _compute_opt_reserve(self) -> int:
        """Compute the size required for the OPT RR, padding excluded"""
        if self.opt is None:
            return 0
        size = 11  # 1 byte owner, 2 bytes type, 2 bytes class, 4 bytes TTL, 2 bytes rdlen
        for opt in self.opt:
            size += len(opt.to_wire())
        return size

    def _compute_tsig_reserve(self) -> int:
        """Compute the size required for the TSIG RR"""
        if self.tsig is None:
            return 0
        return 100  # This is an estimate; actual size may vary

    def to_wire(self, origin: Optional[dns.name.Name]=None, max_size: int=0, multi: bool=False, tsig_ctx: Optional[Any]=None, prepend_length: bool=False, prefer_truncation: bool=False, **kw: Dict[str, Any]) -> bytes:
        """Return a string containing the message in DNS compressed wire
        format.

        Additional keyword arguments are passed to the RRset ``to_wire()``
        method.

        *origin*, a ``dns.name.Name`` or ``None``, the origin to be appended
        to any relative names.  If ``None``, and the message has an origin
        attribute that is not ``None``, then it will be used.

        *max_size*, an ``int``, the maximum size of the wire format
        output; default is 0, which means "the message's request
        payload, if nonzero, or 65535".

        *multi*, a ``bool``, should be set to ``True`` if this message is
        part of a multiple message sequence.

        *tsig_ctx*, a ``dns.tsig.HMACTSig`` or ``dns.tsig.GSSTSig`` object, the
        ongoing TSIG context, used when signing zone transfers.

        *prepend_length*, a ``bool``, should be set to ``True`` if the caller
        wants the message length prepended to the message itself.  This is
        useful for messages sent over TCP, TLS (DoT), or QUIC (DoQ).

        *prefer_truncation*, a ``bool``, should be set to ``True`` if the caller
        wants the message to be truncated if it would otherwise exceed the
        maximum length.  If the truncation occurs before the additional section,
        the TC bit will be set.

        Raises ``dns.exception.TooBig`` if *max_size* was exceeded.

        Returns a ``bytes``.
        """
        if origin is None:
            origin = self.origin
        if max_size == 0:
            max_size = self.request_payload if self.request_payload != 0 else 65535

        r = dns.renderer.Renderer(self.id, self.flags, max_size, origin)
        for rrset in self.question:
            r.add_question(rrset.name, rrset.rdtype, rrset.rdclass)
        for rrset in self.answer:
            r.add_rrset(dns.renderer.ANSWER, rrset, **kw)
        for rrset in self.authority:
            r.add_rrset(dns.renderer.AUTHORITY, rrset, **kw)
        for rrset in self.additional:
            r.add_rrset(dns.renderer.ADDITIONAL, rrset, **kw)
        r.add_edns(self.edns, self.ednsflags, self.payload, self.options)
        r.write_header()
        if self.tsig:
            r.add_tsig(self.tsig, self.tsig_ctx, self.tsig_error)
        wire = r.get_wire()

        if prepend_length:
            wire = struct.pack("!H", len(wire)) + wire

        return wire

    def use_tsig(self, keyring: Any, keyname: Optional[Union[dns.name.Name, str]]=None, fudge: int=300, original_id: Optional[int]=None, tsig_error: int=0, other_data: bytes=b'', algorithm: Union[dns.name.Name, str]=dns.tsig.default_algorithm) -> None:
        """When sending, a TSIG signature using the specified key
        should be added.

        *key*, a ``dns.tsig.Key`` is the key to use.  If a key is specified,
        the *keyring* and *algorithm* fields are not used.

        *keyring*, a ``dict``, ``callable`` or ``dns.tsig.Key``, is either
        the TSIG keyring or key to use.

        The format of a keyring dict is a mapping from TSIG key name, as
        ``dns.name.Name`` to ``dns.tsig.Key`` or a TSIG secret, a ``bytes``.
        If a ``dict`` *keyring* is specified but a *keyname* is not, the key
        used will be the first key in the *keyring*.  Note that the order of
        keys in a dictionary is not defined, so applications should supply a
        keyname when a ``dict`` keyring is used, unless they know the keyring
        contains only one key.  If a ``callable`` keyring is specified, the
        callable will be called with the message and the keyname, and is
        expected to return a key.

        *keyname*, a ``dns.name.Name``, ``str`` or ``None``, the name of
        this TSIG key to use; defaults to ``None``.  If *keyring* is a
        ``dict``, the key must be defined in it.  If *keyring* is a
        ``dns.tsig.Key``, this is ignored.

        *fudge*, an ``int``, the TSIG time fudge.

        *original_id*, an ``int``, the TSIG original id.  If ``None``,
        the message's id is used.

        *tsig_error*, an ``int``, the TSIG error code.

        *other_data*, a ``bytes``, the TSIG other data.

        *algorithm*, a ``dns.name.Name`` or ``str``, the TSIG algorithm to use.  This is
        only used if *keyring* is a ``dict``, and the key entry is a ``bytes``.
        """
        self.keyring = keyring
        if isinstance(keyname, str):
            keyname = dns.name.from_text(keyname)
        self.keyname = keyname
        self.tsig = dns.tsig.Key(algorithm=algorithm, name=keyname, secret=keyring[keyname] if isinstance(keyring, dict) else keyring)
        self.fudge = fudge
        if original_id is None:
            original_id = self.id
        self.original_id = original_id
        self.tsig_error = tsig_error
        self.other_data = other_data

    def use_edns(self, edns: Optional[Union[int, bool]]=0, ednsflags: int=0, payload: int=DEFAULT_EDNS_PAYLOAD, request_payload: Optional[int]=None, options: Optional[List[dns.edns.Option]]=None, pad: int=0) -> None:
        """Configure EDNS behavior.

        *edns*, an ``int``, is the EDNS level to use.  Specifying ``None``, ``False``,
        or ``-1`` means "do not use EDNS", and in this case the other parameters are
        ignored.  Specifying ``True`` is equivalent to specifying 0, i.e. "use EDNS0".

        *ednsflags*, an ``int``, the EDNS flag values.

        *payload*, an ``int``, is the EDNS sender's payload field, which is the maximum
        size of UDP datagram the sender can handle.  I.e. how big a response to this
        message can be.

        *request_payload*, an ``int``, is the EDNS payload size to use when sending this
        message.  If not specified, defaults to the value of *payload*.

        *options*, a list of ``dns.edns.Option`` objects or ``None``, the EDNS options.

        *pad*, a non-negative ``int``.  If 0, the default, do not pad; otherwise add
        padding bytes to make the message size a multiple of *pad*.  Note that if
        padding is non-zero, an EDNS PADDING option will always be added to the
        message.
        """
        if edns is None or edns is False or edns == -1:
            self.edns = -1
            return
        if edns is True:
            edns = 0
        self.edns = edns
        self.ednsflags = ednsflags
        self.payload = payload
        if request_payload is None:
            request_payload = payload
        self.request_payload = request_payload
        self.options = [] if options is None else options
        self.pad = pad
        if pad != 0:
            self.options.append(dns.edns.PaddingOption())

    def want_dnssec(self, wanted: bool=True) -> None:
        """Enable or disable 'DNSSEC desired' flag in requests.

        *wanted*, a ``bool``.  If ``True``, then DNSSEC data is
        desired in the response, EDNS is enabled if required, and then
        the DO bit is set.  If ``False``, the DO bit is cleared if
        EDNS is enabled.
        """
        if wanted:
            self.ednsflags |= dns.flags.DO
            if self.edns == -1:
                self.use_edns()
        elif self.edns >= 0:
            self.ednsflags &= ~dns.flags.DO

    def rcode(self) -> dns.rcode.Rcode:
        """Return the rcode.

        Returns a ``dns.rcode.Rcode``.
        """
        return dns.rcode.Rcode(self.flags & 0xF)

    def set_rcode(self, rcode: dns.rcode.Rcode) -> None:
        """Set the rcode.

        *rcode*, a ``dns.rcode.Rcode``, is the rcode to set.
        """
        self.flags &= ~0xF
        self.flags |= dns.rcode.Rcode.make(rcode) & 0xF

    def opcode(self) -> dns.opcode.Opcode:
        """Return the opcode.

        Returns a ``dns.opcode.Opcode``.
        """
        return dns.opcode.Opcode((self.flags >> 11) & 0xF)

    def set_opcode(self, opcode: dns.opcode.Opcode) -> None:
        """Set the opcode.

        *opcode*, a ``dns.opcode.Opcode``, is the opcode to set.
        """
        self.flags &= ~0x7800
        self.flags |= (dns.opcode.Opcode.make(opcode) & 0xF) << 11

class ChainingResult:
    """The result of a call to dns.message.QueryMessage.resolve_chaining().

    The ``answer`` attribute is the answer RRSet, or ``None`` if it doesn't
    exist.

    The ``canonical_name`` attribute is the canonical name after all
    chaining has been applied (this is the same name as ``rrset.name`` in cases
    where rrset is not ``None``).

    The ``minimum_ttl`` attribute is the minimum TTL, i.e. the TTL to
    use if caching the data.  It is the smallest of all the CNAME TTLs
    and either the answer TTL if it exists or the SOA TTL and SOA
    minimum values for negative answers.

    The ``cnames`` attribute is a list of all the CNAME RRSets followed to
    get to the canonical name.
    """

    def __init__(self, canonical_name: dns.name.Name, answer: Optional[dns.rrset.RRset], minimum_ttl: int, cnames: List[dns.rrset.RRset]):
        self.canonical_name = canonical_name
        self.answer = answer
        self.minimum_ttl = minimum_ttl
        self.cnames = cnames

class QueryMessage(Message):

    def resolve_chaining(self) -> ChainingResult:
        """Follow the CNAME chain in the response to determine the answer
        RRset.

        Raises ``dns.message.NotQueryResponse`` if the message is not
        a response.

        Raises ``dns.message.ChainTooLong`` if the CNAME chain is too long.

        Raises ``dns.message.AnswerForNXDOMAIN`` if the rcode is NXDOMAIN
        but an answer was found.

        Raises ``dns.exception.FormError`` if the question count is not 1.

        Returns a ChainingResult object.
        """
        if not dns.opcode.is_response(self.flags):
            raise NotQueryResponse

        if len(self.question) != 1:
            raise dns.exception.FormError

        question = self.question[0]
        qname = question.name
        qtype = question.rdtype
        qclass = question.rdclass
        canonical_name = qname
        cnames = []
        current_name = qname
        answer = None
        count = 0
        while count < MAX_CHAIN:
            for rrset in self.answer:
                if rrset.name != current_name:
                    continue
                if rrset.rdclass != qclass:
                    continue
                if rrset.rdtype == qtype:
                    answer = rrset
                    canonical_name = rrset.name
                    return ChainingResult(canonical_name, answer, min(rrset.ttl for rrset in cnames + [answer] if rrset), cnames)
                if rrset.rdtype == dns.rdatatype.CNAME:
                    cnames.append(rrset)
                    current_name = rrset[0].target
                    canonical_name = current_name
                    break
            else:
                break
            count += 1

        if count >= MAX_CHAIN:
            raise ChainTooLong

        if self.rcode() == dns.rcode.NXDOMAIN and answer:
            raise AnswerForNXDOMAIN

        return ChainingResult(canonical_name, answer, min(rrset.ttl for rrset in cnames if rrset), cnames)

    def canonical_name(self) -> dns.name.Name:
        """Return the canonical name of the first name in the question
        section.

        Raises ``dns.message.NotQueryResponse`` if the message is not
        a response.

        Raises ``dns.message.ChainTooLong`` if the CNAME chain is too long.

        Raises ``dns.message.AnswerForNXDOMAIN`` if the rcode is NXDOMAIN
        but an answer was found.

        Raises ``dns.exception.FormError`` if the question count is not 1.
        """
        return self.resolve_chaining().canonical_name

class _WireReader:
    """Wire format reader.

    parser: the binary parser
    message: The message object being built
    initialize_message: Callback to set message parsing options
    question_only: Are we only reading the question?
    one_rr_per_rrset: Put each RR into its own RRset?
    keyring: TSIG keyring
    ignore_trailing: Ignore trailing junk at end of request?
    multi: Is this message part of a multi-message sequence?
    DNS dynamic updates.
    continue_on_error: try to extract as much information as possible from
    the message, accumulating MessageErrors in the *errors* attribute instead of
    raising them.
    """

    def __init__(self, wire, initialize_message, question_only=False, one_rr_per_rrset=False, ignore_trailing=False, keyring=None, multi=False, continue_on_error=False):
        self.parser = dns.wire.Parser(wire)
        self.message = None
        self.initialize_message = initialize_message
        self.question_only = question_only
        self.one_rr_per_rrset = one_rr_per_rrset
        self.ignore_trailing = ignore_trailing
        self.keyring = keyring
        self.multi = multi
        self.continue_on_error = continue_on_error
        self.errors = []

    def _get_question(self, section_number, qcount):
        """Read the next *qcount* records from the wire data and add them to
        the question section.
        """
        for _ in range(qcount):
            (qname, qtype, qclass) = self.parser.get_question()
            self.question.append(dns.rrset.RRset(qname, qclass, qtype))

    def _get_section(self, section_number, count):
        """Read the next I{count} records from the wire data and add them to
        the specified section.

        section_number: the section of the message to which to add records
        count: the number of records to read
        """
        section = self.sections[section_number]
        for _ in range(count):
            rr = self.parser.get_rr()
            if self.one_rr_per_rrset:
                rrset = dns.rrset.RRset(rr.name, rr.rdclass, rr.rdtype)
                rrset.add(rr)
                section.append(rrset)
            else:
                for rrset in section:
                    if rrset.name == rr.name and rrset.rdclass == rr.rdclass and rrset.rdtype == rr.rdtype:
                        rrset.add(rr)
                        break
                else:
                    rrset = dns.rrset.RRset(rr.name, rr.rdclass, rr.rdtype)
                    rrset.add(rr)
                    section.append(rrset)

    def read(self):
        """Read a wire format DNS message and build a dns.message.Message
        object."""
        self.message = Message(self.parser.get_uint16())
        self.message.flags = self.parser.get_uint16()
        qcount = self.parser.get_uint16()
        ancount = self.parser.get_uint16()
        aucount = self.parser.get_uint16()
        adcount = self.parser.get_uint16()

        self.initialize_message(self.message)

        try:
            self._get_question(MessageSection.QUESTION, qcount)
            if not self.question_only:
                self._get_section(MessageSection.ANSWER, ancount)
                self._get_section(MessageSection.AUTHORITY, aucount)
                self._get_section(MessageSection.ADDITIONAL, adcount)
        except dns.exception.FormError:
            if self.continue_on_error:
                self.errors.append(MessageError(sys.exc_info()[1], self.parser.current))
            else:
                raise

        if self.keyring:
            self.message.keyring = self.keyring
        if self.keyname is not None:
            self.message.keyname = self.keyname
        if self.multi:
            self.message.multi = True

        return self.message

def from_wire(wire: bytes, keyring: Optional[Any]=None, request_mac: Optional[bytes]=b'', xfr: bool=False, origin: Optional[dns.name.Name]=None, tsig_ctx: Optional[Union[dns.tsig.HMACTSig, dns.tsig.GSSTSig]]=None, multi: bool=False, question_only: bool=False, one_rr_per_rrset: bool=False, ignore_trailing: bool=False, raise_on_truncation: bool=False, continue_on_error: bool=False) -> Message:
    """Convert a DNS wire format message into a message object.

    *keyring*, a ``dns.tsig.Key`` or ``dict``, the key or keyring to use if the message
    is signed.

    *request_mac*, a ``bytes`` or ``None``.  If the message is a response to a
    TSIG-signed request, *request_mac* should be set to the MAC of that request.

    *xfr*, a ``bool``, should be set to ``True`` if this message is part of a zone
    transfer.

    *origin*, a ``dns.name.Name`` or ``None``.  If the message is part of a zone
    transfer, *origin* should be the origin name of the zone.  If not ``None``, names
    will be relativized to the origin.

    *tsig_ctx*, a ``dns.tsig.HMACTSig`` or ``dns.tsig.GSSTSig`` object, the ongoing TSIG
    context, used when validating zone transfers.

    *multi*, a ``bool``, should be set to ``True`` if this message is part of a multiple
    message sequence.

    *question_only*, a ``bool``.  If ``True``, read only up to the end of the question
    section.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing junk at end of the
    message.

    *raise_on_truncation*, a ``bool``.  If ``True``, raise an exception if the TC bit is
    set.

    *continue_on_error*, a ``bool``.  If ``True``, try to continue parsing even if
    errors occur.  Erroneous rdata will be ignored.  Errors will be accumulated as a
    list of MessageError objects in the message's ``errors`` attribute.  This option is
    recommended only for DNS analysis tools, or for use in a server as part of an error
    handling path.  The default is ``False``.

    Raises ``dns.message.ShortHeader`` if the message is less than 12 octets long.

    Raises ``dns.message.TrailingJunk`` if there were octets in the message past the end
    of the proper DNS message, and *ignore_trailing* is ``False``.

    Raises ``dns.message.BadEDNS`` if an OPT record was in the wrong section, or
    occurred more than once.

    Raises ``dns.message.BadTSIG`` if a TSIG record was not the last record of the
    additional data section.

    Raises ``dns.message.Truncated`` if the TC flag is set and *raise_on_truncation* is
    ``True``.

    Returns a ``dns.message.Message``.
    """
    pass

class _TextReader:
    """Text format reader.

    tok: the tokenizer.
    message: The message object being built.
    DNS dynamic updates.
    last_name: The most recently read name when building a message object.
    one_rr_per_rrset: Put each RR into its own RRset?
    origin: The origin for relative names
    relativize: relativize names?
    relativize_to: the origin to relativize to.
    """

    def __init__(self, text, idna_codec, one_rr_per_rrset=False, origin=None, relativize=True, relativize_to=None):
        self.message = None
        self.tok = dns.tokenizer.Tokenizer(text, idna_codec=idna_codec)
        self.last_name = None
        self.one_rr_per_rrset = one_rr_per_rrset
        self.origin = origin
        self.relativize = relativize
        self.relativize_to = relativize_to
        self.id = None
        self.edns = -1
        self.ednsflags = 0
        self.payload = DEFAULT_EDNS_PAYLOAD
        self.rcode = None
        self.opcode = dns.opcode.QUERY
        self.flags = 0

    def _header_line(self, _):
        """Process one line from the text format header section."""
        pass

    def _question_line(self, section_number):
        """Process one line from the text format question section."""
        pass

    def _rr_line(self, section_number):
        """Process one line from the text format answer, authority, or
        additional data sections.
        """
        pass

    def read(self):
        """Read a text format DNS message and build a dns.message.Message
        object."""
        pass

def from_text(text: str, idna_codec: Optional[dns.name.IDNACodec]=None, one_rr_per_rrset: bool=False, origin: Optional[dns.name.Name]=None, relativize: bool=True, relativize_to: Optional[dns.name.Name]=None) -> Message:
    """Convert the text format message into a message object.

    The reader stops after reading the first blank line in the input to
    facilitate reading multiple messages from a single file with
    ``dns.message.from_file()``.

    *text*, a ``str``, the text format message.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, then each RR is put
    into its own rrset.  The default is ``False``.

    *origin*, a ``dns.name.Name`` (or ``None``), the
    origin to use for relative names.

    *relativize*, a ``bool``.  If true, name will be relativized.

    *relativize_to*, a ``dns.name.Name`` (or ``None``), the origin to use
    when relativizing names.  If not set, the *origin* value will be used.

    Raises ``dns.message.UnknownHeaderField`` if a header is unknown.

    Raises ``dns.exception.SyntaxError`` if the text is badly formed.

    Returns a ``dns.message.Message object``
    """
    pass

def from_file(f: Any, idna_codec: Optional[dns.name.IDNACodec]=None, one_rr_per_rrset: bool=False) -> Message:
    """Read the next text format message from the specified file.

    Message blocks are separated by a single blank line.

    *f*, a ``file`` or ``str``.  If *f* is text, it is treated as the
    pathname of a file to open.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, then each RR is put
    into its own rrset.  The default is ``False``.

    Raises ``dns.message.UnknownHeaderField`` if a header is unknown.

    Raises ``dns.exception.SyntaxError`` if the text is badly formed.

    Returns a ``dns.message.Message object``
    """
    pass

def make_query(qname: Union[dns.name.Name, str], rdtype: Union[dns.rdatatype.RdataType, str], rdclass: Union[dns.rdataclass.RdataClass, str]=dns.rdataclass.IN, use_edns: Optional[Union[int, bool]]=None, want_dnssec: bool=False, ednsflags: Optional[int]=None, payload: Optional[int]=None, request_payload: Optional[int]=None, options: Optional[List[dns.edns.Option]]=None, idna_codec: Optional[dns.name.IDNACodec]=None, id: Optional[int]=None, flags: int=dns.flags.RD, pad: int=0) -> QueryMessage:
    """Make a query message.

    The query name, type, and class may all be specified either
    as objects of the appropriate type, or as strings.

    The query will have a randomly chosen query id, and its DNS flags
    will be set to dns.flags.RD.

    qname, a ``dns.name.Name`` or ``str``, the query name.

    *rdtype*, an ``int`` or ``str``, the desired rdata type.

    *rdclass*, an ``int`` or ``str``,  the desired rdata class; the default
    is class IN.

    *use_edns*, an ``int``, ``bool`` or ``None``.  The EDNS level to use; the
    default is ``None``.  If ``None``, EDNS will be enabled only if other
    parameters (*ednsflags*, *payload*, *request_payload*, or *options*) are
    set.
    See the description of dns.message.Message.use_edns() for the possible
    values for use_edns and their meanings.

    *want_dnssec*, a ``bool``.  If ``True``, DNSSEC data is desired.

    *ednsflags*, an ``int``, the EDNS flag values.

    *payload*, an ``int``, is the EDNS sender's payload field, which is the
    maximum size of UDP datagram the sender can handle.  I.e. how big
    a response to this message can be.

    *request_payload*, an ``int``, is the EDNS payload size to use when
    sending this message.  If not specified, defaults to the value of
    *payload*.

    *options*, a list of ``dns.edns.Option`` objects or ``None``, the EDNS
    options.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    *id*, an ``int`` or ``None``, the desired query id.  The default is
    ``None``, which generates a random query id.

    *flags*, an ``int``, the desired query flags.  The default is
    ``dns.flags.RD``.

    *pad*, a non-negative ``int``.  If 0, the default, do not pad; otherwise add
    padding bytes to make the message size a multiple of *pad*.  Note that if
    padding is non-zero, an EDNS PADDING option will always be added to the
    message.

    Returns a ``dns.message.QueryMessage``
    """
    pass

def make_response(query: Message, recursion_available: bool=False, our_payload: int=8192, fudge: int=300, tsig_error: int=0, pad: Optional[int]=None) -> Message:
    """Make a message which is a response for the specified query.
    The message returned is really a response skeleton; it has all of the infrastructure
    required of a response, but none of the content.

    The response's question section is a shallow copy of the query's question section,
    so the query's question RRsets should not be changed.

    *query*, a ``dns.message.Message``, the query to respond to.

    *recursion_available*, a ``bool``, should RA be set in the response?

    *our_payload*, an ``int``, the payload size to advertise in EDNS responses.

    *fudge*, an ``int``, the TSIG time fudge.

    *tsig_error*, an ``int``, the TSIG error.

    *pad*, a non-negative ``int`` or ``None``.  If 0, the default, do not pad; otherwise
    if not ``None`` add padding bytes to make the message size a multiple of *pad*.
    Note that if padding is non-zero, an EDNS PADDING option will always be added to the
    message.  If ``None``, add padding following RFC 8467, namely if the request is
    padded, pad the response to 468 otherwise do not pad.

    Returns a ``dns.message.Message`` object whose specific class is appropriate for the
    query.  For example, if query is a ``dns.update.UpdateMessage``, response will be
    too.
    """
    pass
QUESTION = MessageSection.QUESTION
ANSWER = MessageSection.ANSWER
AUTHORITY = MessageSection.AUTHORITY
ADDITIONAL = MessageSection.ADDITIONAL
