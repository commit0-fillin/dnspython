"""Help for building DNS wire format messages"""
import contextlib
import io
import random
import struct
import time
import dns.exception
import dns.tsig
QUESTION = 0
ANSWER = 1
AUTHORITY = 2
ADDITIONAL = 3

class Renderer:
    """Helper class for building DNS wire-format messages.

    Most applications can use the higher-level L{dns.message.Message}
    class and its to_wire() method to generate wire-format messages.
    This class is for those applications which need finer control
    over the generation of messages.

    Typical use::

        r = dns.renderer.Renderer(id=1, flags=0x80, max_size=512)
        r.add_question(qname, qtype, qclass)
        r.add_rrset(dns.renderer.ANSWER, rrset_1)
        r.add_rrset(dns.renderer.ANSWER, rrset_2)
        r.add_rrset(dns.renderer.AUTHORITY, ns_rrset)
        r.add_rrset(dns.renderer.ADDITIONAL, ad_rrset_1)
        r.add_rrset(dns.renderer.ADDITIONAL, ad_rrset_2)
        r.add_edns(0, 0, 4096)
        r.write_header()
        r.add_tsig(keyname, secret, 300, 1, 0, '', request_mac)
        wire = r.get_wire()

    If padding is going to be used, then the OPT record MUST be
    written after everything else in the additional section except for
    the TSIG (if any).

    output, an io.BytesIO, where rendering is written

    id: the message id

    flags: the message flags

    max_size: the maximum size of the message

    origin: the origin to use when rendering relative names

    compress: the compression table

    section: an int, the section currently being rendered

    counts: list of the number of RRs in each section

    mac: the MAC of the rendered message (if TSIG was used)
    """

    def __init__(self, id=None, flags=0, max_size=65535, origin=None):
        """Initialize a new renderer."""
        self.output = io.BytesIO()
        if id is None:
            self.id = random.randint(0, 65535)
        else:
            self.id = id
        self.flags = flags
        self.max_size = max_size
        self.origin = origin
        self.compress = {}
        self.section = QUESTION
        self.counts = [0, 0, 0, 0]
        self.output.write(b'\x00' * 12)  # Placeholder for header
        self.mac = ''
        self.reserved = 0
        self.was_padded = False

        # Validate input parameters
        if not isinstance(self.id, int) or not 0 <= self.id <= 65535:
            raise ValueError("ID must be an integer between 0 and 65535")
        if not isinstance(self.flags, int) or not 0 <= self.flags <= 65535:
            raise ValueError("Flags must be an integer between 0 and 65535")
        if not isinstance(self.max_size, int) or self.max_size <= 0:
            raise ValueError("Max size must be a positive integer")
        if origin is not None and not isinstance(origin, dns.name.Name):
            raise TypeError("Origin must be a dns.name.Name object or None")

        # Initialize compression dictionary with root
        self.compress[dns.name.root] = 0

    def _rollback(self, where):
        """Truncate the output buffer at offset *where*, and remove any
        compression table entries that pointed beyond the truncation
        point.
        """
        self.output.seek(where)
        self.output.truncate()
        for k, v in list(self.compress.items()):
            if v >= where:
                del self.compress[k]

    def _set_section(self, section):
        """Set the renderer's current section.

        Sections must be rendered order: QUESTION, ANSWER, AUTHORITY,
        ADDITIONAL.  Sections may be empty.

        Raises dns.exception.FormError if an attempt was made to set
        a section value less than the current section.
        """
        if self.section != section:
            if self.section < section:
                self.section = section
            else:
                raise dns.exception.FormError('sections must be rendered in order')

    def add_question(self, qname, rdtype, rdclass=dns.rdataclass.IN):
        """Add a question to the message."""
        self._set_section(QUESTION)
        before = self.output.tell()
        qname.to_wire(self.output, self.compress, self.origin)
        self.output.write(struct.pack("!HH", rdtype, rdclass))
        after = self.output.tell()
        self.counts[QUESTION] += 1
        return (before, after)

    def add_rrset(self, section, rrset, **kw):
        """Add the rrset to the specified section.

        Any keyword arguments are passed on to the rdataset's to_wire()
        routine.
        """
        self._set_section(section)
        before = self.output.tell()
        n = rrset.name.to_wire(self.output, self.compress, self.origin)
        self.output.write(struct.pack("!HHI", rrset.rdtype, rrset.rdclass, rrset.ttl))
        rdataset_start = self.output.tell()
        self.output.write(b'\x00\x00')  # placeholder for rdlen
        n += rrset.to_wire(self.output, self.compress, self.origin, **kw)
        after = self.output.tell()
        rdlen = after - rdataset_start - 2
        self.output.seek(rdataset_start)
        self.output.write(struct.pack("!H", rdlen))
        self.output.seek(after)
        self.counts[section] += 1
        return (before, after)

    def add_rdataset(self, section, name, rdataset, **kw):
        """Add the rdataset to the specified section, using the specified
        name as the owner name.

        Any keyword arguments are passed on to the rdataset's to_wire()
        routine.
        """
        self._set_section(section)
        before = self.output.tell()
        name.to_wire(self.output, self.compress, self.origin)
        self.output.write(struct.pack("!HHI", rdataset.rdtype, rdataset.rdclass, rdataset.ttl))
        rdataset_start = self.output.tell()
        self.output.write(b'\x00\x00')  # placeholder for rdlen
        n = rdataset.to_wire(self.output, self.compress, self.origin, **kw)
        after = self.output.tell()
        rdlen = after - rdataset_start - 2
        self.output.seek(rdataset_start)
        self.output.write(struct.pack("!H", rdlen))
        self.output.seek(after)
        self.counts[section] += 1
        return (before, after)

    def add_opt(self, opt, pad=0, opt_size=0, tsig_size=0):
        """Add *opt* to the additional section, applying padding if desired.  The
        padding will take the specified precomputed OPT size and TSIG size into
        account.

        Note that we don't have reliable way of knowing how big a GSS-TSIG digest
        might be, so we we might not get an even multiple of the pad in that case."""
        self._set_section(ADDITIONAL)
        before = self.output.tell()
        start = before
        self.output.write(b'\x00')  # empty name
        self.output.write(struct.pack('!HHIH', opt.rdtype, opt.rdclass,
                                      opt.ttl, 0))  # placeholder for rdlen
        rdata_start = self.output.tell()
        opt.to_wire(self.output)
        after = self.output.tell()
        rdlen = after - rdata_start
        if pad:
            desired_length = (((before + opt_size + tsig_size - 1) // pad) + 1) * pad
            current_length = after + tsig_size
            pad_length = desired_length - current_length
            if pad_length > 0:
                self.output.write(b'\x00' * pad_length)
                after += pad_length
                rdlen += pad_length
        self.output.seek(start + 11)
        self.output.write(struct.pack('!H', rdlen))
        self.output.seek(after)
        self.counts[ADDITIONAL] += 1
        return (before, after)

    def add_edns(self, edns, ednsflags, payload, options=None):
        """Add an EDNS OPT record to the message."""
        # pylint: disable=unused-argument
        opt = dns.message.OPT(payload, dns.rdatatype.OPT, ednsflags)
        if options is not None:
            for option in options:
                opt.add_option(option)
        self.add_opt(opt)

    def add_tsig(self, keyname, secret, fudge, id, tsig_error, other_data, request_mac, algorithm=dns.tsig.default_algorithm):
        """Add a TSIG signature to the message."""
        self._set_section(ADDITIONAL)
        before = self.output.tell()
        s = self.output.getvalue()
        (tsig_rdata, mac, ctx) = dns.tsig.sign(s, keyname, secret, int(time.time()),
                                               fudge, id, tsig_error, other_data,
                                               request_mac, algorithm=algorithm)
        keyname.to_wire(self.output, self.compress, self.origin)
        self.output.write(struct.pack('!HHIH', dns.rdatatype.TSIG, dns.rdataclass.ANY,
                                      0, 0))
        rdata_start = self.output.tell()
        self.output.write(tsig_rdata)
        after = self.output.tell()
        rdlen = after - rdata_start
        self.output.seek(rdata_start - 2)
        self.output.write(struct.pack('!H', rdlen))
        self.output.seek(after)
        self.counts[ADDITIONAL] += 1
        self.mac = mac
        return (before, after)

    def add_multi_tsig(self, ctx, keyname, secret, fudge, id, tsig_error, other_data, request_mac, algorithm=dns.tsig.default_algorithm):
        """Add a TSIG signature to the message. Unlike add_tsig(), this can be
        used for a series of consecutive DNS envelopes, e.g. for a zone
        transfer over TCP [RFC2845, 4.4].

        For the first message in the sequence, give ctx=None. For each
        subsequent message, give the ctx that was returned from the
        add_multi_tsig() call for the previous message."""
        self._set_section(ADDITIONAL)
        before = self.output.tell()
        s = self.output.getvalue()
        (tsig_rdata, mac, ctx) = dns.tsig.sign(s, keyname, secret, int(time.time()),
                                               fudge, id, tsig_error, other_data,
                                               request_mac, algorithm=algorithm,
                                               ctx=ctx, multi=True)
        keyname.to_wire(self.output, self.compress, self.origin)
        self.output.write(struct.pack('!HHIH', dns.rdatatype.TSIG, dns.rdataclass.ANY,
                                      0, 0))
        rdata_start = self.output.tell()
        self.output.write(tsig_rdata)
        after = self.output.tell()
        rdlen = after - rdata_start
        self.output.seek(rdata_start - 2)
        self.output.write(struct.pack('!H', rdlen))
        self.output.seek(after)
        self.counts[ADDITIONAL] += 1
        self.mac = mac
        return (ctx, before, after)

    def write_header(self):
        """Write the DNS message header.

        Writing the DNS message header is done after all sections
        have been rendered, but before the optional TSIG signature
        is added.
        """
        self.output.seek(0)
        self.output.write(struct.pack('!HHHHHH', self.id, self.flags,
                                      self.counts[0], self.counts[1],
                                      self.counts[2], self.counts[3]))

    def get_wire(self):
        """Return the wire format message."""
        return self.output.getvalue()

    def reserve(self, size: int) -> None:
        """Reserve *size* bytes."""
        self.reserved += size

    def release_reserved(self) -> None:
        """Release the reserved bytes."""
        self.reserved = 0
