from typing import Type
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519
from dns.dnssecalgs.cryptography import CryptographyPrivateKey, CryptographyPublicKey
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY

class PublicEDDSA(CryptographyPublicKey):

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per RFC 8080, section 3."""
        return self.key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

class PrivateEDDSA(CryptographyPrivateKey):
    public_cls: Type[PublicEDDSA]

    def sign(self, data: bytes, verify: bool=False) -> bytes:
        """Sign using a private key per RFC 8080, section 4."""
        signature = self.key.sign(data)
        if verify:
            public_key = self.key.public_key()
            try:
                public_key.verify(signature, data)
            except:
                raise ValueError("Signature verification failed")
        return signature

class PublicED25519(PublicEDDSA):
    key: ed25519.Ed25519PublicKey
    key_cls = ed25519.Ed25519PublicKey
    algorithm = Algorithm.ED25519

class PrivateED25519(PrivateEDDSA):
    key: ed25519.Ed25519PrivateKey
    key_cls = ed25519.Ed25519PrivateKey
    public_cls = PublicED25519

class PublicED448(PublicEDDSA):
    key: ed448.Ed448PublicKey
    key_cls = ed448.Ed448PublicKey
    algorithm = Algorithm.ED448

class PrivateED448(PrivateEDDSA):
    key: ed448.Ed448PrivateKey
    key_cls = ed448.Ed448PrivateKey
    public_cls = PublicED448
