import secrets 
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import cryptography

class Crypto:
    def __init__(self):
        self._private_key = X25519PrivateKey.from_private_bytes(self._generate_private_key_bytes())
        self._shared_key = None

    def _generate_private_key_bytes(self) -> bytes:  # TODO: switch to custom PRNG?, possibly HMAC-SHA256
        return secrets.token_bytes(32)

    def public_key(self) -> bytes:
        return self._private_key.public_key().public_bytes_raw()
    
    def compute_shared_key(self, peer_public_key: bytes) -> None:
        self._shared_key = self._private_key.exchange(X25519PublicKey.from_public_bytes(peer_public_key))