from typing import Any, List, Optional, Tuple, Union
import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdataset
import dns.rdatatype
import dns.serial
import dns.transaction
import dns.tsig
import dns.zone

class TransferError(dns.exception.DNSException):
    """A zone transfer response got a non-zero rcode."""

    def __init__(self, rcode):
        message = 'Zone transfer error: %s' % dns.rcode.to_text(rcode)
        super().__init__(message)
        self.rcode = rcode

class SerialWentBackwards(dns.exception.FormError):
    """The current serial number is less than the serial we know."""

class UseTCP(dns.exception.DNSException):
    """This IXFR cannot be completed with UDP."""

class Inbound:
    """
    State machine for zone transfers.
    """

    def __init__(self, txn_manager: dns.transaction.TransactionManager, rdtype: dns.rdatatype.RdataType=dns.rdatatype.AXFR, serial: Optional[int]=None, is_udp: bool=False):
        """Initialize an inbound zone transfer.

        *txn_manager* is a :py:class:`dns.transaction.TransactionManager`.

        *rdtype* can be `dns.rdatatype.AXFR` or `dns.rdatatype.IXFR`

        *serial* is the base serial number for IXFRs, and is required in
        that case.

        *is_udp*, a ``bool`` indidicates if UDP is being used for this
        XFR.
        """
        self.txn_manager = txn_manager
        self.txn: Optional[dns.transaction.Transaction] = None
        self.rdtype = rdtype
        if rdtype == dns.rdatatype.IXFR:
            if serial is None:
                raise ValueError('a starting serial must be supplied for IXFRs')
        elif is_udp:
            raise ValueError('is_udp specified for AXFR')
        self.serial = serial
        self.is_udp = is_udp
        _, _, self.origin = txn_manager.origin_information()
        self.soa_rdataset: Optional[dns.rdataset.Rdataset] = None
        self.done = False
        self.expecting_SOA = False
        self.delete_mode = False

    def process_message(self, message: dns.message.Message) -> bool:
        """Process one message in the transfer.

        The message should have the same relativization as was specified when
        the `dns.xfr.Inbound` was created.  The message should also have been
        created with `one_rr_per_rrset=True` because order matters.

        Returns `True` if the transfer is complete, and `False` otherwise.
        """
        if not self.txn:
            self.txn = self.txn_manager.writer()

        if self.rdtype == dns.rdatatype.AXFR:
            return self._process_axfr_message(message)
        elif self.rdtype == dns.rdatatype.IXFR:
            return self._process_ixfr_message(message)
        else:
            raise ValueError(f"Unsupported transfer type: {self.rdtype}")

    def _process_axfr_message(self, message: dns.message.Message) -> bool:
        for rrset in message.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                if self.soa_rdataset is None:
                    self.soa_rdataset = rrset
                else:
                    # Second SOA marks the end of the transfer
                    self.txn.commit()
                    self.done = True
                    return True
            self.txn.add(rrset)
        return False

    def _process_ixfr_message(self, message: dns.message.Message) -> bool:
        for rrset in message.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                if self.soa_rdataset is None:
                    self.soa_rdataset = rrset
                    if dns.serial.Serial(rrset[0].serial) <= dns.serial.Serial(self.serial):
                        # If the SOA serial is less than or equal to our serial,
                        # we're up to date, so we're done
                        self.done = True
                        return True
                else:
                    if rrset == self.soa_rdataset:
                        # We've reached the end of the IXFR
                        self.txn.commit()
                        self.done = True
                        return True
                    else:
                        # Toggle delete_mode
                        self.delete_mode = not self.delete_mode
            else:
                if self.delete_mode:
                    self.txn.delete(rrset)
                else:
                    self.txn.add(rrset)
        return False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.txn:
            self.txn.rollback()
        return False

def make_query(txn_manager: dns.transaction.TransactionManager, serial: Optional[int]=0, use_edns: Optional[Union[int, bool]]=None, ednsflags: Optional[int]=None, payload: Optional[int]=None, request_payload: Optional[int]=None, options: Optional[List[dns.edns.Option]]=None, keyring: Any=None, keyname: Optional[dns.name.Name]=None, keyalgorithm: Union[dns.name.Name, str]=dns.tsig.default_algorithm) -> Tuple[dns.message.QueryMessage, Optional[int]]:
    """Make an AXFR or IXFR query.

    *txn_manager* is a ``dns.transaction.TransactionManager``, typically a
    ``dns.zone.Zone``.

    *serial* is an ``int`` or ``None``.  If 0, then IXFR will be
    attempted using the most recent serial number from the
    *txn_manager*; it is the caller's responsibility to ensure there
    are no write transactions active that could invalidate the
    retrieved serial.  If a serial cannot be determined, AXFR will be
    forced.  Other integer values are the starting serial to use.
    ``None`` forces an AXFR.

    Please see the documentation for :py:func:`dns.message.make_query` and
    :py:func:`dns.message.Message.use_tsig` for details on the other parameters
    to this function.

    Returns a `(query, serial)` tuple.
    """
    rdtype = dns.rdatatype.AXFR
    if serial is not None:
        rdtype = dns.rdatatype.IXFR
        if serial == 0:
            with txn_manager.reader() as txn:
                try:
                    serial = txn.get_soa().serial
                except Exception:
                    serial = None
                    rdtype = dns.rdatatype.AXFR

    origin = txn_manager.from_wire_origin()
    if origin is None:
        raise ValueError("Transaction manager has no origin")

    q = dns.message.make_query(origin, rdtype, dns.rdataclass.IN,
                               use_edns=use_edns, ednsflags=ednsflags,
                               payload=payload, request_payload=request_payload,
                               options=options)

    if rdtype == dns.rdatatype.IXFR:
        rrset = dns.rrset.from_text(origin, 0, dns.rdataclass.IN, dns.rdatatype.SOA,
                                    f"0 0 {serial} 0 0 0 0")
        q.authority = [rrset]

    if keyring is not None:
        q.use_tsig(keyring, keyname, algorithm=keyalgorithm)

    return (q, serial)

def extract_serial_from_query(query: dns.message.Message) -> Optional[int]:
    """Extract the SOA serial number from query if it is an IXFR and return
    it, otherwise return None.

    *query* is a dns.message.QueryMessage that is an IXFR or AXFR request.

    Raises if the query is not an IXFR or AXFR, or if an IXFR doesn't have
    an appropriate SOA RRset in the authority section.
    """
    if query.question[0].rdtype == dns.rdatatype.IXFR:
        if len(query.authority) != 1:
            raise dns.exception.FormError("IXFR query does not have exactly one SOA")
        rrset = query.authority[0]
        if rrset.rdtype != dns.rdatatype.SOA:
            raise dns.exception.FormError("IXFR query authority is not an SOA")
        return rrset[0].serial
    elif query.question[0].rdtype == dns.rdatatype.AXFR:
        return None
    else:
        raise ValueError("Query is not an IXFR or AXFR")
