import secrets 
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

class Crypto:
    def __init__(self):
        hkdf_exp = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=None)
        rand = secrets.token_bytes(32)
        h = hmac.HMAC(b'\x00' * 32, hashes.SHA256())
        h.update(rand)
        prk = h.finalize() # pseudo random key
        private_key_bytes = bytearray(hkdf_exp.derive(prk))
        private_key_bytes[0] &= 248
        private_key_bytes[31] &= 127
        private_key_bytes[31] |= 64
        self._private_key = X25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
        self._shared_key = None
        self._iv = None

    def public_key(self) -> bytes:
        return self._private_key.public_key().public_bytes_raw()
    
    def compute_shared_key(self, peer_public_key: bytes) -> None:
        shared_secret = self._private_key.exchange(X25519PublicKey.from_public_bytes(peer_public_key))
        h = hmac.HMAC(b'\x00' * 32, hashes.SHA256())
        h.update(shared_secret)
        prk = h.finalize()

        hkdf_exp_aes = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"aes-key")
        hkdf_exp_iv  = HKDFExpand(algorithm=hashes.SHA256(), length=12, info=b"iv")

        self._shared_key = hkdf_exp_aes.derive(prk)
        self._iv = hkdf_exp_iv.derive(prk)