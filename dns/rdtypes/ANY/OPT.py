import struct
import dns.edns
import dns.exception
import dns.immutable
import dns.rdata

@dns.immutable.immutable
class OPT(dns.rdata.Rdata):
    """OPT record"""
    __slots__ = ['options']

    def __init__(self, rdclass, rdtype, options):
        """Initialize an OPT rdata.

        *rdclass*, an ``int`` is the rdataclass of the Rdata,
        which is also the payload size.

        *rdtype*, an ``int`` is the rdatatype of the Rdata.

        *options*, a tuple of ``bytes``
        """
        super().__init__(rdclass, rdtype)

        def as_option(option):
            if not isinstance(option, dns.edns.Option):
                raise ValueError('option is not a dns.edns.option')
            return option
        self.options = self._as_tuple(options, as_option)

    @property
    def payload(self):
        """payload size"""
        return self.rdclass
