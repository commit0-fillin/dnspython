"""DNS Zones."""
import re
import sys
from typing import Any, Iterable, List, Optional, Set, Tuple, Union
import dns.exception
import dns.grange
import dns.name
import dns.node
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.tokenizer
import dns.transaction
import dns.ttl

class UnknownOrigin(dns.exception.DNSException):
    """Unknown origin"""

class CNAMEAndOtherData(dns.exception.DNSException):
    """A node has a CNAME and other data"""
SavedStateType = Tuple[dns.tokenizer.Tokenizer, Optional[dns.name.Name], Optional[dns.name.Name], Optional[Any], int, bool, int, bool]

class Reader:
    """Read a DNS zone file into a transaction."""

    def __init__(self, tok: dns.tokenizer.Tokenizer, rdclass: dns.rdataclass.RdataClass, txn: dns.transaction.Transaction, allow_include: bool=False, allow_directives: Union[bool, Iterable[str]]=True, force_name: Optional[dns.name.Name]=None, force_ttl: Optional[int]=None, force_rdclass: Optional[dns.rdataclass.RdataClass]=None, force_rdtype: Optional[dns.rdatatype.RdataType]=None, default_ttl: Optional[int]=None):
        self.tok = tok
        self.zone_origin, self.relativize, _ = txn.manager.origin_information()
        self.current_origin = self.zone_origin
        self.last_ttl = 0
        self.last_ttl_known = False
        if force_ttl is not None:
            default_ttl = force_ttl
        if default_ttl is None:
            self.default_ttl = 0
            self.default_ttl_known = False
        else:
            self.default_ttl = default_ttl
            self.default_ttl_known = True
        self.last_name = self.current_origin
        self.zone_rdclass = rdclass
        self.txn = txn
        self.saved_state: List[SavedStateType] = []
        self.current_file: Optional[Any] = None
        self.allowed_directives: Set[str]
        if allow_directives is True:
            self.allowed_directives = {'$GENERATE', '$ORIGIN', '$TTL'}
            if allow_include:
                self.allowed_directives.add('$INCLUDE')
        elif allow_directives is False:
            self.allowed_directives = set()
        else:
            self.allowed_directives = set((_upper_dollarize(d) for d in allow_directives))
        self.force_name = force_name
        self.force_ttl = force_ttl
        self.force_rdclass = force_rdclass
        self.force_rdtype = force_rdtype
        self.txn.check_put_rdataset(_check_cname_and_other_data)

    def _rr_line(self):
        """Process one line from a DNS zone file."""
        token = self.tok.get()
        if token.is_whitespace():
            token = self.tok.get()
        if token.is_eol():
            return
        if token.is_comment():
            return
        self.tok.unget(token)
        
        (name, ttl, rdclass, rdtype) = self._parse_rr_header()
        
        if rdtype == 'SOA' and self.zone_origin is None:
            self.zone_origin = name
        
        rd = dns.rdata.from_text(rdclass, rdtype, self.tok, name, self.relativize, self.zone_origin, self.txn.manager.get_class())
        
        if self.last_name is None:
            self.last_name = name
        
        self.txn.add(name, ttl, rd)

    def _generate_line(self):
        """Process one line containing the GENERATE statement from a DNS
        zone file."""
        token = self.tok.get()
        if not token.is_identifier() or token.value != '$GENERATE':
            raise dns.exception.SyntaxError('$GENERATE expected')
        
        start, stop, step = dns.grange.from_text(self.tok.get().value)
        name = self.tok.get().value
        rdtype = self.tok.get().value
        rdata = self.tok.get().value
        
        for i in range(start, stop + 1, step):
            n = name.replace('$', str(i))
            r = rdata.replace('$', str(i))
            
            name = dns.name.from_text(n, self.zone_origin, self.txn.manager.get_class())
            rds = dns.rdata.from_text(self.zone_rdclass, rdtype, r, self.zone_origin, self.relativize)
            
            self.txn.add(name, self.last_ttl, rds)

    def read(self) -> None:
        """Read a DNS zone file and build a zone object.

        @raises dns.zone.NoSOA: No SOA RR was found at the zone origin
        @raises dns.zone.NoNS: No NS RRset was found at the zone origin
        """
        try:
            while 1:
                token = self.tok.get(True, True)
                if token.is_eof():
                    break
                if token.is_eol():
                    continue
                self.tok.unget(token)
                if token.value == '$ORIGIN':
                    self._origin_line()
                elif token.value == '$TTL':
                    self._ttl_line()
                elif token.value == '$INCLUDE':
                    self._include_line()
                elif token.value == '$GENERATE':
                    self._generate_line()
                else:
                    self._rr_line()
        except dns.exception.SyntaxError as e:
            raise dns.exception.SyntaxError(f'syntax error at ({self.tok.line}, {self.tok.file}): {e}')
        
        # Check if we have SOA and NS records
        if not self.txn.get(self.zone_origin, dns.rdatatype.SOA):
            raise dns.zone.NoSOA
        if not self.txn.get(self.zone_origin, dns.rdatatype.NS):
            raise dns.zone.NoNS

class RRsetsReaderTransaction(dns.transaction.Transaction):

    def __init__(self, manager, replacement, read_only):
        assert not read_only
        super().__init__(manager, replacement, read_only)
        self.rdatasets = {}

class RRSetsReaderManager(dns.transaction.TransactionManager):

    def __init__(self, origin=dns.name.root, relativize=False, rdclass=dns.rdataclass.IN):
        self.origin = origin
        self.relativize = relativize
        self.rdclass = rdclass
        self.rrsets = []

def read_rrsets(text: Any, name: Optional[Union[dns.name.Name, str]]=None, ttl: Optional[int]=None, rdclass: Optional[Union[dns.rdataclass.RdataClass, str]]=dns.rdataclass.IN, default_rdclass: Union[dns.rdataclass.RdataClass, str]=dns.rdataclass.IN, rdtype: Optional[Union[dns.rdatatype.RdataType, str]]=None, default_ttl: Optional[Union[int, str]]=None, idna_codec: Optional[dns.name.IDNACodec]=None, origin: Optional[Union[dns.name.Name, str]]=dns.name.root, relativize: bool=False) -> List[dns.rrset.RRset]:
    """Read one or more rrsets from the specified text, possibly subject
    to restrictions.

    *text*, a file object or a string, is the input to process.

    *name*, a string, ``dns.name.Name``, or ``None``, is the owner name of
    the rrset.  If not ``None``, then the owner name is "forced", and the
    input must not specify an owner name.  If ``None``, then any owner names
    are allowed and must be present in the input.

    *ttl*, an ``int``, string, or None.  If not ``None``, the the TTL is
    forced to be the specified value and the input must not specify a TTL.
    If ``None``, then a TTL may be specified in the input.  If it is not
    specified, then the *default_ttl* will be used.

    *rdclass*, a ``dns.rdataclass.RdataClass``, string, or ``None``.  If
    not ``None``, then the class is forced to the specified value, and the
    input must not specify a class.  If ``None``, then the input may specify
    a class that matches *default_rdclass*.  Note that it is not possible to
    return rrsets with differing classes; specifying ``None`` for the class
    simply allows the user to optionally type a class as that may be convenient
    when cutting and pasting.

    *default_rdclass*, a ``dns.rdataclass.RdataClass`` or string.  The class
    of the returned rrsets.

    *rdtype*, a ``dns.rdatatype.RdataType``, string, or ``None``.  If not
    ``None``, then the type is forced to the specified value, and the
    input must not specify a type.  If ``None``, then a type must be present
    for each RR.

    *default_ttl*, an ``int``, string, or ``None``.  If not ``None``, then if
    the TTL is not forced and is not specified, then this value will be used.
    if ``None``, then if the TTL is not forced an error will occur if the TTL
    is not specified.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.  Note that codecs only apply to the owner name; dnspython does
    not do IDNA for names in rdata, as there is no IDNA zonefile format.

    *origin*, a string, ``dns.name.Name``, or ``None``, is the origin for any
    relative names in the input, and also the origin to relativize to if
    *relativize* is ``True``.

    *relativize*, a bool.  If ``True``, names are relativized to the *origin*;
    if ``False`` then any relative names in the input are made absolute by
    appending the *origin*.
    """
    if isinstance(text, str):
        text = io.StringIO(text)
    
    if isinstance(origin, str):
        origin = dns.name.from_text(origin, dns.name.root)
    
    if isinstance(rdclass, str):
        rdclass = dns.rdataclass.from_text(rdclass)
    if isinstance(default_rdclass, str):
        default_rdclass = dns.rdataclass.from_text(default_rdclass)
    
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)
    
    if isinstance(ttl, str):
        ttl = dns.ttl.from_text(ttl)
    if isinstance(default_ttl, str):
        default_ttl = dns.ttl.from_text(default_ttl)
    
    tok = dns.tokenizer.Tokenizer(text, filename='<string>')
    rrsets = []
    
    while True:
        token = tok.get()
        if token.is_eof():
            break
        tok.unget(token)
        
        current_name = name
        current_ttl = ttl if ttl is not None else default_ttl
        current_rdclass = rdclass if rdclass is not None else default_rdclass
        current_rdtype = rdtype
        
        if current_name is None:
            current_name = dns.name.from_text(tok.get().value, origin, idna_codec)
        
        if current_ttl is None:
            token = tok.get()
            if token.is_identifier():
                current_ttl = dns.ttl.from_text(token.value)
            else:
                tok.unget(token)
        
        if current_rdclass is None:
            token = tok.get()
            if token.is_identifier():
                current_rdclass = dns.rdataclass.from_text(token.value)
            else:
                tok.unget(token)
        
        if current_rdtype is None:
            current_rdtype = dns.rdatatype.from_text(tok.get().value)
        
        rdatas = []
        while not tok.is_eol():
            rdatas.append(dns.rdata.from_text(current_rdclass, current_rdtype, tok, origin, relativize))
        
        rrset = dns.rrset.from_rdata_list(current_name, current_ttl, rdatas)
        rrsets.append(rrset)
    
    return rrsets
