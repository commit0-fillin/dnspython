from abc import ABC, abstractmethod
from typing import Any, Optional, Type
import dns.rdataclass
import dns.rdatatype
from dns.dnssectypes import Algorithm
from dns.exception import AlgorithmKeyMismatch
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag

class GenericPublicKey(ABC):
    algorithm: Algorithm

    @abstractmethod
    def __init__(self, key: Any) -> None:
        self.key = key

    @abstractmethod
    def verify(self, signature: bytes, data: bytes) -> None:
        """Verify signed DNSSEC data"""
        raise NotImplementedError("Subclass must implement abstract method")

    @abstractmethod
    def encode_key_bytes(self) -> bytes:
        """Encode key as bytes for DNSKEY"""
        raise NotImplementedError("Subclass must implement abstract method")

    def to_dnskey(self, flags: int=Flag.ZONE, protocol: int=3) -> DNSKEY:
        """Return public key as DNSKEY"""
        return DNSKEY(dns.rdataclass.IN, dns.rdatatype.DNSKEY, flags, protocol, self.algorithm, self.encode_key_bytes())

    @classmethod
    @abstractmethod
    def from_dnskey(cls, key: DNSKEY) -> 'GenericPublicKey':
        """Create public key from DNSKEY"""
        raise NotImplementedError("Subclass must implement abstract method")

    @classmethod
    @abstractmethod
    def from_pem(cls, public_pem: bytes) -> 'GenericPublicKey':
        """Create public key from PEM-encoded SubjectPublicKeyInfo as specified
        in RFC 5280"""
        raise NotImplementedError("Subclass must implement abstract method")

    @abstractmethod
    def to_pem(self) -> bytes:
        """Return public-key as PEM-encoded SubjectPublicKeyInfo as specified
        in RFC 5280"""
        raise NotImplementedError("Subclass must implement abstract method")

class GenericPrivateKey(ABC):
    public_cls: Type[GenericPublicKey]

    @abstractmethod
    def __init__(self, key: Any) -> None:
        self.key = key

    @abstractmethod
    def sign(self, data: bytes, verify: bool=False) -> bytes:
        """Sign DNSSEC data"""
        raise NotImplementedError("Subclass must implement abstract method")

    @abstractmethod
    def public_key(self) -> 'GenericPublicKey':
        """Return public key instance"""
        raise NotImplementedError("Subclass must implement abstract method")

    @classmethod
    @abstractmethod
    def from_pem(cls, private_pem: bytes, password: Optional[bytes]=None) -> 'GenericPrivateKey':
        """Create private key from PEM-encoded PKCS#8"""
        raise NotImplementedError("Subclass must implement abstract method")

    @abstractmethod
    def to_pem(self, password: Optional[bytes]=None) -> bytes:
        """Return private key as PEM-encoded PKCS#8"""
        raise NotImplementedError("Subclass must implement abstract method")
