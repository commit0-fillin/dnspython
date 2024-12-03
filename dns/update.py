"""DNS Dynamic Update Support"""
from typing import Any, List, Optional, Union
import dns.message
import dns.name
import dns.opcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.tsig

class UpdateSection(dns.enum.IntEnum):
    """Update sections"""
    ZONE = 0
    PREREQ = 1
    UPDATE = 2
    ADDITIONAL = 3

class UpdateMessage(dns.message.Message):
    _section_enum = UpdateSection

    def __init__(self, zone: Optional[Union[dns.name.Name, str]]=None, rdclass: dns.rdataclass.RdataClass=dns.rdataclass.IN, keyring: Optional[Any]=None, keyname: Optional[dns.name.Name]=None, keyalgorithm: Union[dns.name.Name, str]=dns.tsig.default_algorithm, id: Optional[int]=None):
        """Initialize a new DNS Update object.

        See the documentation of the Message class for a complete
        description of the keyring dictionary.

        *zone*, a ``dns.name.Name``, ``str``, or ``None``, the zone
        which is being updated.  ``None`` should only be used by dnspython's
        message constructors, as a zone is required for the convenience
        methods like ``add()``, ``replace()``, etc.

        *rdclass*, an ``int`` or ``str``, the class of the zone.

        The *keyring*, *keyname*, and *keyalgorithm* parameters are passed to
        ``use_tsig()``; see its documentation for details.
        """
        super().__init__(id=id)
        self.flags |= dns.opcode.to_flags(dns.opcode.UPDATE)
        if isinstance(zone, str):
            zone = dns.name.from_text(zone)
        self.origin = zone
        rdclass = dns.rdataclass.RdataClass.make(rdclass)
        self.zone_rdclass = rdclass
        if self.origin:
            self.find_rrset(self.zone, self.origin, rdclass, dns.rdatatype.SOA, create=True, force_unique=True)
        if keyring is not None:
            self.use_tsig(keyring, keyname, algorithm=keyalgorithm)

    @property
    def zone(self) -> List[dns.rrset.RRset]:
        """The zone section."""
        return self.sections[ZONE]

    @property
    def prerequisite(self) -> List[dns.rrset.RRset]:
        """The prerequisite section."""
        return self.sections[PREREQ]

    @property
    def update(self) -> List[dns.rrset.RRset]:
        """The update section."""
        return self.sections[UPDATE]

    def _add_rr(self, name, ttl, rd, deleting=None, section=None):
        """Add a single RR to the update section."""
        if section is None:
            section = self.update
        rrset = self.find_rrset(section, name, rd.rdclass, rd.rdtype,
                                rd.covers, deleting, True, True)
        rrset.add(rd, ttl)

    def _add(self, replace, section, name, *args):
        """Add records.

        *replace* is the replacement mode.  If ``False``,
        RRs are added to an existing RRset; if ``True``, the RRset
        is replaced with the specified contents.  The second
        argument is the section to add to.  The third argument
        is always a name.  The other arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...
        """
        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if isinstance(args[0], dns.rdataset.Rdataset):
            rdataset = args[0]
            for rdata in rdataset:
                self._add_rr(name, rdataset.ttl, rdata, None, section)
        else:
            args = list(args)
            ttl = int(args.pop(0))
            if isinstance(args[0], dns.rdata.Rdata):
                rd = args[0]
                self._add_rr(name, ttl, rd, None, section)
            else:
                rdtype = dns.rdatatype.RdataType.make(args.pop(0))
                rd = dns.rdata.from_text(self.zone_rdclass, rdtype, args[0],
                                         origin=self.origin, relativize=False)
                self._add_rr(name, ttl, rd, None, section)
        if replace:
            rrset = self.find_rrset(section, name, rd.rdclass, rd.rdtype,
                                    rd.covers, None, False, True)
            rrset.delete(rdata)

    def add(self, name: Union[dns.name.Name, str], *args: Any) -> None:
        """Add records.

        The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...
        """
        self._add(False, self.update, name, *args)

    def delete(self, name: Union[dns.name.Name, str], *args: Any) -> None:
        """Delete records.

        The first argument is always a name.  The other
        arguments can be:

                - *empty*

                - rdataset...

                - rdata...

                - rdtype, [string...]
        """
        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if len(args) == 0:
            rrset = self.find_rrset(self.update, name, dns.rdataclass.ANY,
                                    dns.rdatatype.ANY, dns.rdatatype.NONE,
                                    dns.rdataclass.ANY, True, True)
        elif isinstance(args[0], dns.rdataset.Rdataset):
            rrset = self.find_rrset(self.update, name, args[0].rdclass,
                                    args[0].rdtype, args[0].covers,
                                    dns.rdataclass.NONE, True, True)
            for rd in args[0]:
                rrset.add(rd)
        else:
            args = list(args)
            if isinstance(args[0], dns.rdata.Rdata):
                rd = args.pop(0)
                rrset = self.find_rrset(self.update, name, rd.rdclass,
                                        rd.rdtype, rd.covers,
                                        dns.rdataclass.NONE, True, True)
                rrset.add(rd)
            else:
                rdtype = dns.rdatatype.RdataType.make(args.pop(0))
                if len(args) > 0:
                    rd = dns.rdata.from_text(self.zone_rdclass, rdtype,
                                             args[0], origin=self.origin,
                                             relativize=False)
                    rrset = self.find_rrset(self.update, name,
                                            self.zone_rdclass, rdtype,
                                            dns.rdatatype.NONE,
                                            dns.rdataclass.NONE, True, True)
                    rrset.add(rd)
                else:
                    rrset = self.find_rrset(self.update, name,
                                            self.zone_rdclass, rdtype,
                                            dns.rdatatype.NONE,
                                            dns.rdataclass.ANY, True, True)

    def replace(self, name: Union[dns.name.Name, str], *args: Any) -> None:
        """Replace records.

        The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...

        Note that if you want to replace the entire node, you should do
        a delete of the name followed by one or more calls to add.
        """
        self._add(True, self.update, name, *args)

    def present(self, name: Union[dns.name.Name, str], *args: Any) -> None:
        """Require that an owner name (and optionally an rdata type,
        or specific rdataset) exists as a prerequisite to the
        execution of the update.

        The first argument is always a name.
        The other arguments can be:

                - rdataset...

                - rdata...

                - rdtype, string...
        """
        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if len(args) == 0:
            rrset = self.find_rrset(self.prerequisite, name,
                                    dns.rdataclass.ANY, dns.rdatatype.ANY,
                                    dns.rdatatype.NONE, None, True, True)
        elif isinstance(args[0], dns.rdataset.Rdataset):
            rrset = self.find_rrset(self.prerequisite, name,
                                    dns.rdataclass.IN, args[0].rdtype,
                                    args[0].covers, None, True, True)
            for rd in args[0]:
                rrset.add(rd)
        else:
            args = list(args)
            if isinstance(args[0], dns.rdata.Rdata):
                rd = args.pop(0)
                rrset = self.find_rrset(self.prerequisite, name,
                                        dns.rdataclass.IN, rd.rdtype,
                                        rd.covers, None, True, True)
                rrset.add(rd)
            else:
                rdtype = dns.rdatatype.RdataType.make(args.pop(0))
                if len(args) > 0:
                    rd = dns.rdata.from_text(dns.rdataclass.IN, rdtype,
                                             args[0], origin=self.origin,
                                             relativize=False)
                    rrset = self.find_rrset(self.prerequisite, name,
                                            dns.rdataclass.IN, rdtype,
                                            dns.rdatatype.NONE, None,
                                            True, True)
                    rrset.add(rd)
                else:
                    rrset = self.find_rrset(self.prerequisite, name,
                                            dns.rdataclass.IN, rdtype,
                                            dns.rdatatype.NONE, None,
                                            True, True)

    def absent(self, name: Union[dns.name.Name, str], rdtype: Optional[Union[dns.rdatatype.RdataType, str]]=None) -> None:
        """Require that an owner name (and optionally an rdata type) does
        not exist as a prerequisite to the execution of the update."""
        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if rdtype is None:
            rrset = self.find_rrset(self.prerequisite, name,
                                    dns.rdataclass.NONE, dns.rdatatype.ANY,
                                    dns.rdatatype.NONE, None, True, True)
        else:
            if isinstance(rdtype, str):
                rdtype = dns.rdatatype.from_text(rdtype)
            rrset = self.find_rrset(self.prerequisite, name,
                                    dns.rdataclass.NONE, rdtype,
                                    dns.rdatatype.NONE, None, True, True)
Update = UpdateMessage
ZONE = UpdateSection.ZONE
PREREQ = UpdateSection.PREREQ
UPDATE = UpdateSection.UPDATE
ADDITIONAL = UpdateSection.ADDITIONAL
