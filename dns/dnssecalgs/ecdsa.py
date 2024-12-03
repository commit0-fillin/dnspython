from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from dns.dnssecalgs.cryptography import CryptographyPrivateKey, CryptographyPublicKey
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY

class PublicECDSA(CryptographyPublicKey):
    key: ec.EllipticCurvePublicKey
    key_cls = ec.EllipticCurvePublicKey
    algorithm: Algorithm
    chosen_hash: hashes.HashAlgorithm
    curve: ec.EllipticCurve
    octets: int

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per RFC 6605, section 4."""
        public_numbers = self.key.public_numbers()
        x = public_numbers.x.to_bytes(self.octets, byteorder='big')
        y = public_numbers.y.to_bytes(self.octets, byteorder='big')
        return x + y

class PrivateECDSA(CryptographyPrivateKey):
    key: ec.EllipticCurvePrivateKey
    key_cls = ec.EllipticCurvePrivateKey
    public_cls = PublicECDSA

    def sign(self, data: bytes, verify: bool=False) -> bytes:
        """Sign using a private key per RFC 6605, section 4."""
        signature = self.key.sign(
            data,
            ec.ECDSA(self.public_cls.chosen_hash)
        )
        r, s = utils.decode_dss_signature(signature)
        r_bytes = r.to_bytes(self.public_cls.octets, byteorder='big')
        s_bytes = s.to_bytes(self.public_cls.octets, byteorder='big')
        
        if verify:
            public_key = self.key.public_key()
            try:
                public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(self.public_cls.chosen_hash)
                )
            except Exception:
                raise ValueError("Signature verification failed")
        
        return r_bytes + s_bytes

class PublicECDSAP256SHA256(PublicECDSA):
    algorithm = Algorithm.ECDSAP256SHA256
    chosen_hash = hashes.SHA256()
    curve = ec.SECP256R1()
    octets = 32

class PrivateECDSAP256SHA256(PrivateECDSA):
    public_cls = PublicECDSAP256SHA256

class PublicECDSAP384SHA384(PublicECDSA):
    algorithm = Algorithm.ECDSAP384SHA384
    chosen_hash = hashes.SHA384()
    curve = ec.SECP384R1()
    octets = 48

class PrivateECDSAP384SHA384(PrivateECDSA):
    public_cls = PublicECDSAP384SHA384
