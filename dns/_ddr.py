import socket
import ssl
import time
from urllib.parse import urlparse
import dns.asyncbackend
import dns.inet
import dns.name
import dns.nameserver
import dns.query
import dns.rdtypes.svcbbase
_local_resolver_name = dns.name.from_text('_dns.resolver.arpa')

class _SVCBInfo:

    def __init__(self, bootstrap_address, port, hostname, nameservers):
        self.bootstrap_address = bootstrap_address
        self.port = port
        self.hostname = hostname
        self.nameservers = nameservers

    def ddr_check_certificate(self, cert):
        """Verify that the _SVCBInfo's address is in the cert's subjectAltName (SAN)"""
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            if san:
                for name in san.value:
                    if isinstance(name, x509.DNSName):
                        if name.value == self.hostname:
                            return True
                    elif isinstance(name, x509.IPAddress):
                        if name.value == self.bootstrap_address:
                            return True
            return False
        except x509.ExtensionNotFound:
            return False

def _get_nameservers_sync(answer, lifetime):
    """Return a list of TLS-validated resolver nameservers extracted from an SVCB
    answer."""
    nameservers = []
    start_time = time.time()
    for rrset in answer.answer:
        for rr in rrset:
            if isinstance(rr, dns.rdtypes.svcbbase.SVCBBase):
                svcb_info = _SVCBInfo(
                    bootstrap_address=rr.target.to_text(),
                    port=rr.port,
                    hostname=rr.target.to_text(),
                    nameservers=[]
                )
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((svcb_info.bootstrap_address, svcb_info.port), timeout=lifetime) as sock:
                        with context.wrap_socket(sock, server_hostname=svcb_info.hostname) as secure_sock:
                            cert = secure_sock.getpeercert()
                            if svcb_info.ddr_check_certificate(cert):
                                nameservers.append(dns.nameserver.Nameserver(svcb_info.bootstrap_address, svcb_info.port, True))
                except (socket.error, ssl.SSLError):
                    pass
            if time.time() - start_time > lifetime:
                break
        if time.time() - start_time > lifetime:
            break
    return nameservers

async def _get_nameservers_async(answer, lifetime):
    """Return a list of TLS-validated resolver nameservers extracted from an SVCB
    answer."""
    nameservers = []
    start_time = time.time()
    for rrset in answer.answer:
        for rr in rrset:
            if isinstance(rr, dns.rdtypes.svcbbase.SVCBBase):
                svcb_info = _SVCBInfo(
                    bootstrap_address=rr.target.to_text(),
                    port=rr.port,
                    hostname=rr.target.to_text(),
                    nameservers=[]
                )
                try:
                    context = ssl.create_default_context()
                    backend = dns.asyncbackend.get_default_backend()
                    async with backend.make_socket(dns.inet.af_for_address(svcb_info.bootstrap_address),
                                                   socket.SOCK_STREAM, 0) as sock:
                        await sock.connect((svcb_info.bootstrap_address, svcb_info.port))
                        ssl_sock = await backend.make_ssl_stream(sock, svcb_info.hostname, context, server_hostname=svcb_info.hostname)
                        cert = ssl_sock.getpeercert()
                        if svcb_info.ddr_check_certificate(cert):
                            nameservers.append(dns.nameserver.Nameserver(svcb_info.bootstrap_address, svcb_info.port, True))
                except (socket.error, ssl.SSLError):
                    pass
            if time.time() - start_time > lifetime:
                break
        if time.time() - start_time > lifetime:
            break
    return nameservers
