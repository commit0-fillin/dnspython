import math
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from dns.dnssecalgs.cryptography import CryptographyPrivateKey, CryptographyPublicKey
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY

class PublicRSA(CryptographyPublicKey):
    key: rsa.RSAPublicKey
    key_cls = rsa.RSAPublicKey
    algorithm: Algorithm
    chosen_hash: hashes.HashAlgorithm

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per RFC 3110, section 2."""
        exponent = self.key.public_numbers().e
        modulus = self.key.public_numbers().n
        exponent_len = (exponent.bit_length() + 7) // 8
        modulus_bytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, byteorder='big')
        
        if exponent_len <= 255:
            return struct.pack('!B', exponent_len) + \
                   exponent.to_bytes(exponent_len, byteorder='big') + \
                   modulus_bytes
        else:
            return struct.pack('!BH', 0, exponent_len) + \
                   exponent.to_bytes(exponent_len, byteorder='big') + \
                   modulus_bytes

class PrivateRSA(CryptographyPrivateKey):
    key: rsa.RSAPrivateKey
    key_cls = rsa.RSAPrivateKey
    public_cls = PublicRSA
    default_public_exponent = 65537

    def sign(self, data: bytes, verify: bool=False) -> bytes:
        """Sign using a private key per RFC 3110, section 3."""
        signature = self.key.sign(
            data,
            padding.PKCS1v15(),
            self.public_cls.chosen_hash
        )
        
        if verify:
            public_key = self.key.public_key()
            try:
                public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    self.public_cls.chosen_hash
                )
            except:
                raise ValueError("Signature verification failed")
        
        return signature

class PublicRSAMD5(PublicRSA):
    algorithm = Algorithm.RSAMD5
    chosen_hash = hashes.MD5()

class PrivateRSAMD5(PrivateRSA):
    public_cls = PublicRSAMD5

class PublicRSASHA1(PublicRSA):
    algorithm = Algorithm.RSASHA1
    chosen_hash = hashes.SHA1()

class PrivateRSASHA1(PrivateRSA):
    public_cls = PublicRSASHA1

class PublicRSASHA1NSEC3SHA1(PublicRSA):
    algorithm = Algorithm.RSASHA1NSEC3SHA1
    chosen_hash = hashes.SHA1()

class PrivateRSASHA1NSEC3SHA1(PrivateRSA):
    public_cls = PublicRSASHA1NSEC3SHA1

class PublicRSASHA256(PublicRSA):
    algorithm = Algorithm.RSASHA256
    chosen_hash = hashes.SHA256()

class PrivateRSASHA256(PrivateRSA):
    public_cls = PublicRSASHA256

class PublicRSASHA512(PublicRSA):
    algorithm = Algorithm.RSASHA512
    chosen_hash = hashes.SHA512()

class PrivateRSASHA512(PrivateRSA):
    public_cls = PublicRSASHA512
