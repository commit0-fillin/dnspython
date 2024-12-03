"""Common DNSSEC-related functions and constants."""
import base64
import contextlib
import functools
import hashlib
import struct
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple, Union, cast
import dns._features
import dns.exception
import dns.name
import dns.node
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.transaction
import dns.zone
from dns.dnssectypes import Algorithm, DSDigest, NSEC3Hash
from dns.exception import AlgorithmKeyMismatch, DeniedByPolicy, UnsupportedAlgorithm, ValidationFailure
from dns.rdtypes.ANY.CDNSKEY import CDNSKEY
from dns.rdtypes.ANY.CDS import CDS
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.NSEC import NSEC, Bitmap
from dns.rdtypes.ANY.NSEC3PARAM import NSEC3PARAM
from dns.rdtypes.ANY.RRSIG import RRSIG, sigtime_to_posixtime
from dns.rdtypes.dnskeybase import Flag
PublicKey = Union['GenericPublicKey', 'rsa.RSAPublicKey', 'ec.EllipticCurvePublicKey', 'ed25519.Ed25519PublicKey', 'ed448.Ed448PublicKey']
PrivateKey = Union['GenericPrivateKey', 'rsa.RSAPrivateKey', 'ec.EllipticCurvePrivateKey', 'ed25519.Ed25519PrivateKey', 'ed448.Ed448PrivateKey']
RRsetSigner = Callable[[dns.transaction.Transaction, dns.rrset.RRset], None]

def algorithm_from_text(text: str) -> Algorithm:
    """Convert text into a DNSSEC algorithm value.

    *text*, a ``str``, the text to convert to into an algorithm value.

    Returns an ``int``.
    """
    text = text.upper()
    try:
        return Algorithm[text]
    except KeyError:
        try:
            return Algorithm(int(text))
        except ValueError:
            raise dns.exception.SyntaxError(f"unknown algorithm '{text}'")

def algorithm_to_text(value: Union[Algorithm, int]) -> str:
    """Convert a DNSSEC algorithm value to text

    *value*, a ``dns.dnssec.Algorithm``.

    Returns a ``str``, the name of a DNSSEC algorithm.
    """
    try:
        return Algorithm(value).name
    except ValueError:
        return str(value)

def to_timestamp(value: Union[datetime, str, float, int]) -> int:
    """Convert various format to a timestamp"""
    if isinstance(value, datetime):
        return int(value.timestamp())
    elif isinstance(value, str):
        try:
            return int(datetime.strptime(value, "%Y%m%d%H%M%S").timestamp())
        except ValueError:
            return int(float(value))
    elif isinstance(value, float):
        return int(value)
    elif isinstance(value, int):
        return value
    else:
        raise ValueError("Unsupported type for timestamp conversion")

def key_id(key: Union[DNSKEY, CDNSKEY]) -> int:
    """Return the key id (a 16-bit number) for the specified key.

    *key*, a ``dns.rdtypes.ANY.DNSKEY.DNSKEY``

    Returns an ``int`` between 0 and 65535
    """
    rdata = dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.DNSKEY, key.to_wire())
    total = 0
    for i, byte in enumerate(rdata.to_wire()):
        if i % 2 == 0:
            total += byte << 8
        else:
            total += byte
    return total & 0xFFFF

class Policy:

    def __init__(self):
        pass

class SimpleDeny(Policy):

    def __init__(self, deny_sign, deny_validate, deny_create_ds, deny_validate_ds):
        super().__init__()
        self._deny_sign = deny_sign
        self._deny_validate = deny_validate
        self._deny_create_ds = deny_create_ds
        self._deny_validate_ds = deny_validate_ds
rfc_8624_policy = SimpleDeny({Algorithm.RSAMD5, Algorithm.DSA, Algorithm.DSANSEC3SHA1, Algorithm.ECCGOST}, {Algorithm.RSAMD5, Algorithm.DSA, Algorithm.DSANSEC3SHA1}, {DSDigest.NULL, DSDigest.SHA1, DSDigest.GOST}, {DSDigest.NULL})
allow_all_policy = SimpleDeny(set(), set(), set(), set())
default_policy = rfc_8624_policy

def make_ds(name: Union[dns.name.Name, str], key: dns.rdata.Rdata, algorithm: Union[DSDigest, str], origin: Optional[dns.name.Name]=None, policy: Optional[Policy]=None, validating: bool=False) -> DS:
    """Create a DS record for a DNSSEC key.

    *name*, a ``dns.name.Name`` or ``str``, the owner name of the DS record.

    *key*, a ``dns.rdtypes.ANY.DNSKEY.DNSKEY`` or ``dns.rdtypes.ANY.DNSKEY.CDNSKEY``,
    the key the DS is about.

    *algorithm*, a ``str`` or ``int`` specifying the hash algorithm.
    The currently supported hashes are "SHA1", "SHA256", and "SHA384". Case
    does not matter for these strings.

    *origin*, a ``dns.name.Name`` or ``None``.  If *key* is a relative name,
    then it will be made absolute using the specified origin.

    *policy*, a ``dns.dnssec.Policy`` or ``None``.  If ``None``, the default policy,
    ``dns.dnssec.default_policy`` is used; this policy defaults to that of RFC 8624.

    *validating*, a ``bool``.  If ``True``, then policy is checked in
    validating mode, i.e. "Is it ok to validate using this digest algorithm?".
    Otherwise the policy is checked in creating mode, i.e. "Is it ok to create a DS with
    this digest algorithm?".

    Raises ``UnsupportedAlgorithm`` if the algorithm is unknown.

    Raises ``DeniedByPolicy`` if the algorithm is denied by policy.

    Returns a ``dns.rdtypes.ANY.DS.DS``
    """
    if isinstance(name, str):
        name = dns.name.from_text(name, origin)
    if isinstance(algorithm, str):
        algorithm = DSDigest[algorithm.upper()]
    
    if policy is None:
        policy = default_policy
    
    if validating:
        if policy._deny_validate_ds and algorithm in policy._deny_validate_ds:
            raise DeniedByPolicy(f"DS digest algorithm {algorithm} denied by policy")
    else:
        if policy._deny_create_ds and algorithm in policy._deny_create_ds:
            raise DeniedByPolicy(f"DS digest algorithm {algorithm} denied by policy")
    
    if not isinstance(key, (DNSKEY, CDNSKEY)):
        raise ValueError("Key must be a DNSKEY or CDNSKEY")
    
    key_wire = key.to_wire()
    digest = _make_hash(algorithm, name.to_wire() + key_wire)
    
    return DS(dns.rdataclass.IN, dns.rdatatype.DS, key.key_tag(), key.algorithm, algorithm, digest)

def make_cds(name: Union[dns.name.Name, str], key: dns.rdata.Rdata, algorithm: Union[DSDigest, str], origin: Optional[dns.name.Name]=None) -> CDS:
    """Create a CDS record for a DNSSEC key.

    *name*, a ``dns.name.Name`` or ``str``, the owner name of the DS record.

    *key*, a ``dns.rdtypes.ANY.DNSKEY.DNSKEY`` or ``dns.rdtypes.ANY.DNSKEY.CDNSKEY``,
    the key the DS is about.

    *algorithm*, a ``str`` or ``int`` specifying the hash algorithm.
    The currently supported hashes are "SHA1", "SHA256", and "SHA384". Case
    does not matter for these strings.

    *origin*, a ``dns.name.Name`` or ``None``.  If *key* is a relative name,
    then it will be made absolute using the specified origin.

    Raises ``UnsupportedAlgorithm`` if the algorithm is unknown.

    Returns a ``dns.rdtypes.ANY.DS.CDS``
    """
    ds = make_ds(name, key, algorithm, origin)
    return CDS(ds.rdclass, dns.rdatatype.CDS, ds.key_tag, ds.algorithm, ds.digest_type, ds.digest)

def _validate_rrsig(rrset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]], rrsig: RRSIG, keys: Dict[dns.name.Name, Union[dns.node.Node, dns.rdataset.Rdataset]], origin: Optional[dns.name.Name]=None, now: Optional[float]=None, policy: Optional[Policy]=None) -> None:
    """Validate an RRset against a single signature rdata, throwing an
    exception if validation is not successful.

    *rrset*, the RRset to validate.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *rrsig*, a ``dns.rdata.Rdata``, the signature to validate.

    *keys*, the key dictionary, used to find the DNSKEY associated
    with a given name.  The dictionary is keyed by a
    ``dns.name.Name``, and has ``dns.node.Node`` or
    ``dns.rdataset.Rdataset`` values.

    *origin*, a ``dns.name.Name`` or ``None``, the origin to use for relative
    names.

    *now*, a ``float`` or ``None``, the time, in seconds since the epoch, to
    use as the current time when validating.  If ``None``, the actual current
    time is used.

    *policy*, a ``dns.dnssec.Policy`` or ``None``.  If ``None``, the default policy,
    ``dns.dnssec.default_policy`` is used; this policy defaults to that of RFC 8624.

    Raises ``ValidationFailure`` if the signature is expired, not yet valid,
    the public key is invalid, the algorithm is unknown, the verification
    fails, etc.

    Raises ``UnsupportedAlgorithm`` if the algorithm is recognized by
    dnspython but not implemented.
    """
    pass

def _validate(rrset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]], rrsigset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]], keys: Dict[dns.name.Name, Union[dns.node.Node, dns.rdataset.Rdataset]], origin: Optional[dns.name.Name]=None, now: Optional[float]=None, policy: Optional[Policy]=None) -> None:
    """Validate an RRset against a signature RRset, throwing an exception
    if none of the signatures validate.

    *rrset*, the RRset to validate.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *rrsigset*, the signature RRset.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *keys*, the key dictionary, used to find the DNSKEY associated
    with a given name.  The dictionary is keyed by a
    ``dns.name.Name``, and has ``dns.node.Node`` or
    ``dns.rdataset.Rdataset`` values.

    *origin*, a ``dns.name.Name``, the origin to use for relative names;
    defaults to None.

    *now*, an ``int`` or ``None``, the time, in seconds since the epoch, to
    use as the current time when validating.  If ``None``, the actual current
    time is used.

    *policy*, a ``dns.dnssec.Policy`` or ``None``.  If ``None``, the default policy,
    ``dns.dnssec.default_policy`` is used; this policy defaults to that of RFC 8624.

    Raises ``ValidationFailure`` if the signature is expired, not yet valid,
    the public key is invalid, the algorithm is unknown, the verification
    fails, etc.
    """
    pass

def _sign(rrset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]], private_key: PrivateKey, signer: dns.name.Name, dnskey: DNSKEY, inception: Optional[Union[datetime, str, int, float]]=None, expiration: Optional[Union[datetime, str, int, float]]=None, lifetime: Optional[int]=None, verify: bool=False, policy: Optional[Policy]=None, origin: Optional[dns.name.Name]=None) -> RRSIG:
    """Sign RRset using private key.

    *rrset*, the RRset to validate.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *private_key*, the private key to use for signing, a
    ``cryptography.hazmat.primitives.asymmetric`` private key class applicable
    for DNSSEC.

    *signer*, a ``dns.name.Name``, the Signer's name.

    *dnskey*, a ``DNSKEY`` matching ``private_key``.

    *inception*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the
    signature inception time.  If ``None``, the current time is used.  If a ``str``, the
    format is "YYYYMMDDHHMMSS" or alternatively the number of seconds since the UNIX
    epoch in text form; this is the same the RRSIG rdata's text form.
    Values of type `int` or `float` are interpreted as seconds since the UNIX epoch.

    *expiration*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the signature
    expiration time.  If ``None``, the expiration time will be the inception time plus
    the value of the *lifetime* parameter.  See the description of *inception* above
    for how the various parameter types are interpreted.

    *lifetime*, an ``int`` or ``None``, the signature lifetime in seconds.  This
    parameter is only meaningful if *expiration* is ``None``.

    *verify*, a ``bool``.  If set to ``True``, the signer will verify signatures
    after they are created; the default is ``False``.

    *policy*, a ``dns.dnssec.Policy`` or ``None``.  If ``None``, the default policy,
    ``dns.dnssec.default_policy`` is used; this policy defaults to that of RFC 8624.

    *origin*, a ``dns.name.Name`` or ``None``.  If ``None``, the default, then all
    names in the rrset (including its owner name) must be absolute; otherwise the
    specified origin will be used to make names absolute when signing.

    Raises ``DeniedByPolicy`` if the signature is denied by policy.
    """
    pass

def _make_rrsig_signature_data(rrset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]], rrsig: RRSIG, origin: Optional[dns.name.Name]=None) -> bytes:
    """Create signature rdata.

    *rrset*, the RRset to sign/validate.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *rrsig*, a ``dns.rdata.Rdata``, the signature to validate, or the
    signature template used when signing.

    *origin*, a ``dns.name.Name`` or ``None``, the origin to use for relative
    names.

    Raises ``UnsupportedAlgorithm`` if the algorithm is recognized by
    dnspython but not implemented.
    """
    pass

def _make_dnskey(public_key: PublicKey, algorithm: Union[int, str], flags: int=Flag.ZONE, protocol: int=3) -> DNSKEY:
    """Convert a public key to DNSKEY Rdata

    *public_key*, a ``PublicKey`` (``GenericPublicKey`` or
    ``cryptography.hazmat.primitives.asymmetric``) to convert.

    *algorithm*, a ``str`` or ``int`` specifying the DNSKEY algorithm.

    *flags*: DNSKEY flags field as an integer.

    *protocol*: DNSKEY protocol field as an integer.

    Raises ``ValueError`` if the specified key algorithm parameters are not
    unsupported, ``TypeError`` if the key type is unsupported,
    `UnsupportedAlgorithm` if the algorithm is unknown and
    `AlgorithmKeyMismatch` if the algorithm does not match the key type.

    Return DNSKEY ``Rdata``.
    """
    pass

def _make_cdnskey(public_key: PublicKey, algorithm: Union[int, str], flags: int=Flag.ZONE, protocol: int=3) -> CDNSKEY:
    """Convert a public key to CDNSKEY Rdata

    *public_key*, the public key to convert, a
    ``cryptography.hazmat.primitives.asymmetric`` public key class applicable
    for DNSSEC.

    *algorithm*, a ``str`` or ``int`` specifying the DNSKEY algorithm.

    *flags*: DNSKEY flags field as an integer.

    *protocol*: DNSKEY protocol field as an integer.

    Raises ``ValueError`` if the specified key algorithm parameters are not
    unsupported, ``TypeError`` if the key type is unsupported,
    `UnsupportedAlgorithm` if the algorithm is unknown and
    `AlgorithmKeyMismatch` if the algorithm does not match the key type.

    Return CDNSKEY ``Rdata``.
    """
    pass

def nsec3_hash(domain: Union[dns.name.Name, str], salt: Optional[Union[str, bytes]], iterations: int, algorithm: Union[int, str]) -> str:
    """
    Calculate the NSEC3 hash, according to
    https://tools.ietf.org/html/rfc5155#section-5

    *domain*, a ``dns.name.Name`` or ``str``, the name to hash.

    *salt*, a ``str``, ``bytes``, or ``None``, the hash salt.  If a
    string, it is decoded as a hex string.

    *iterations*, an ``int``, the number of iterations.

    *algorithm*, a ``str`` or ``int``, the hash algorithm.
    The only defined algorithm is SHA1.

    Returns a ``str``, the encoded NSEC3 hash.
    """
    pass

def make_ds_rdataset(rrset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]], algorithms: Set[Union[DSDigest, str]], origin: Optional[dns.name.Name]=None) -> dns.rdataset.Rdataset:
    """Create a DS record from DNSKEY/CDNSKEY/CDS.

    *rrset*, the RRset to create DS Rdataset for.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *algorithms*, a set of ``str`` or ``int`` specifying the hash algorithms.
    The currently supported hashes are "SHA1", "SHA256", and "SHA384". Case
    does not matter for these strings. If the RRset is a CDS, only digest
    algorithms matching algorithms are accepted.

    *origin*, a ``dns.name.Name`` or ``None``.  If `key` is a relative name,
    then it will be made absolute using the specified origin.

    Raises ``UnsupportedAlgorithm`` if any of the algorithms are unknown and
    ``ValueError`` if the given RRset is not usable.

    Returns a ``dns.rdataset.Rdataset``
    """
    pass

def cds_rdataset_to_ds_rdataset(rdataset: dns.rdataset.Rdataset) -> dns.rdataset.Rdataset:
    """Create a CDS record from DS.

    *rdataset*, a ``dns.rdataset.Rdataset``, to create DS Rdataset for.

    Raises ``ValueError`` if the rdataset is not CDS.

    Returns a ``dns.rdataset.Rdataset``
    """
    pass

def dnskey_rdataset_to_cds_rdataset(name: Union[dns.name.Name, str], rdataset: dns.rdataset.Rdataset, algorithm: Union[DSDigest, str], origin: Optional[dns.name.Name]=None) -> dns.rdataset.Rdataset:
    """Create a CDS record from DNSKEY/CDNSKEY.

    *name*, a ``dns.name.Name`` or ``str``, the owner name of the CDS record.

    *rdataset*, a ``dns.rdataset.Rdataset``, to create DS Rdataset for.

    *algorithm*, a ``str`` or ``int`` specifying the hash algorithm.
    The currently supported hashes are "SHA1", "SHA256", and "SHA384". Case
    does not matter for these strings.

    *origin*, a ``dns.name.Name`` or ``None``.  If `key` is a relative name,
    then it will be made absolute using the specified origin.

    Raises ``UnsupportedAlgorithm`` if the algorithm is unknown or
    ``ValueError`` if the rdataset is not DNSKEY/CDNSKEY.

    Returns a ``dns.rdataset.Rdataset``
    """
    pass

def dnskey_rdataset_to_cdnskey_rdataset(rdataset: dns.rdataset.Rdataset) -> dns.rdataset.Rdataset:
    """Create a CDNSKEY record from DNSKEY.

    *rdataset*, a ``dns.rdataset.Rdataset``, to create CDNSKEY Rdataset for.

    Returns a ``dns.rdataset.Rdataset``
    """
    pass

def default_rrset_signer(txn: dns.transaction.Transaction, rrset: dns.rrset.RRset, signer: dns.name.Name, ksks: List[Tuple[PrivateKey, DNSKEY]], zsks: List[Tuple[PrivateKey, DNSKEY]], inception: Optional[Union[datetime, str, int, float]]=None, expiration: Optional[Union[datetime, str, int, float]]=None, lifetime: Optional[int]=None, policy: Optional[Policy]=None, origin: Optional[dns.name.Name]=None) -> None:
    """Default RRset signer"""
    pass

def sign_zone(zone: dns.zone.Zone, txn: Optional[dns.transaction.Transaction]=None, keys: Optional[List[Tuple[PrivateKey, DNSKEY]]]=None, add_dnskey: bool=True, dnskey_ttl: Optional[int]=None, inception: Optional[Union[datetime, str, int, float]]=None, expiration: Optional[Union[datetime, str, int, float]]=None, lifetime: Optional[int]=None, nsec3: Optional[NSEC3PARAM]=None, rrset_signer: Optional[RRsetSigner]=None, policy: Optional[Policy]=None) -> None:
    """Sign zone.

    *zone*, a ``dns.zone.Zone``, the zone to sign.

    *txn*, a ``dns.transaction.Transaction``, an optional transaction to use for
    signing.

    *keys*, a list of (``PrivateKey``, ``DNSKEY``) tuples, to use for signing. KSK/ZSK
    roles are assigned automatically if the SEP flag is used, otherwise all RRsets are
    signed by all keys.

    *add_dnskey*, a ``bool``.  If ``True``, the default, all specified DNSKEYs are
    automatically added to the zone on signing.

    *dnskey_ttl*, a``int``, specifies the TTL for DNSKEY RRs. If not specified the TTL
    of the existing DNSKEY RRset used or the TTL of the SOA RRset.

    *inception*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the signature
    inception time.  If ``None``, the current time is used.  If a ``str``, the format is
    "YYYYMMDDHHMMSS" or alternatively the number of seconds since the UNIX epoch in text
    form; this is the same the RRSIG rdata's text form. Values of type `int` or `float`
    are interpreted as seconds since the UNIX epoch.

    *expiration*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the signature
    expiration time.  If ``None``, the expiration time will be the inception time plus
    the value of the *lifetime* parameter.  See the description of *inception* above for
    how the various parameter types are interpreted.

    *lifetime*, an ``int`` or ``None``, the signature lifetime in seconds.  This
    parameter is only meaningful if *expiration* is ``None``.

    *nsec3*, a ``NSEC3PARAM`` Rdata, configures signing using NSEC3. Not yet
    implemented.

    *rrset_signer*, a ``Callable``, an optional function for signing RRsets. The
    function requires two arguments: transaction and RRset. If the not specified,
    ``dns.dnssec.default_rrset_signer`` will be used.

    Returns ``None``.
    """
    pass

def _sign_zone_nsec(zone: dns.zone.Zone, txn: dns.transaction.Transaction, rrset_signer: Optional[RRsetSigner]=None) -> None:
    """NSEC zone signer"""
    pass
if dns._features.have('dnssec'):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import dsa
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import ed448
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from dns.dnssecalgs import get_algorithm_cls, get_algorithm_cls_from_dnskey
    from dns.dnssecalgs.base import GenericPrivateKey, GenericPublicKey
    validate = _validate
    validate_rrsig = _validate_rrsig
    sign = _sign
    make_dnskey = _make_dnskey
    make_cdnskey = _make_cdnskey
    _have_pyca = True
else:
    validate = _need_pyca
    validate_rrsig = _need_pyca
    sign = _need_pyca
    make_dnskey = _need_pyca
    make_cdnskey = _need_pyca
    _have_pyca = False
RSAMD5 = Algorithm.RSAMD5
DH = Algorithm.DH
DSA = Algorithm.DSA
ECC = Algorithm.ECC
RSASHA1 = Algorithm.RSASHA1
DSANSEC3SHA1 = Algorithm.DSANSEC3SHA1
RSASHA1NSEC3SHA1 = Algorithm.RSASHA1NSEC3SHA1
RSASHA256 = Algorithm.RSASHA256
RSASHA512 = Algorithm.RSASHA512
ECCGOST = Algorithm.ECCGOST
ECDSAP256SHA256 = Algorithm.ECDSAP256SHA256
ECDSAP384SHA384 = Algorithm.ECDSAP384SHA384
ED25519 = Algorithm.ED25519
ED448 = Algorithm.ED448
INDIRECT = Algorithm.INDIRECT
PRIVATEDNS = Algorithm.PRIVATEDNS
PRIVATEOID = Algorithm.PRIVATEOID
