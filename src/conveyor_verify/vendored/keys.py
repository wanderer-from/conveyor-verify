"""Ed25519 signatures over record hashes (integrity.md §2, §6)."""

from __future__ import annotations

import base64
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey as _NaclSigningKey
from nacl.signing import VerifyKey

from conveyor_verify.vendored.hashing import Domain, hex_to_bytes


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str, expected_len: int) -> bytes:
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64") from exc
    if len(raw) != expected_len:
        raise ValueError(f"expected {expected_len} bytes, got {len(raw)}")
    return raw


def _signed_message(record_hash_hex: str) -> bytes:
    return Domain.SIGNATURE.encode() + hex_to_bytes(record_hash_hex)


@dataclass(frozen=True)
class SigningKey:
    """An Ed25519 key pair. The seed never leaves the process except via `seed_b64`."""

    _key: _NaclSigningKey

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(_NaclSigningKey.generate())

    @classmethod
    def from_seed_b64(cls, seed_b64: str) -> SigningKey:
        return cls(_NaclSigningKey(_unb64(seed_b64, 32)))

    @property
    def seed_b64(self) -> str:
        """32-byte seed, base64. For the SOPS-encrypted key file and the offline backup."""
        return _b64(bytes(self._key))

    @property
    def public_key_b64(self) -> str:
        """32-byte public key, base64: the `signing_keys.public_key` column."""
        return _b64(bytes(self._key.verify_key))

    def sign(self, record_hash_hex: str) -> str:
        """signature = Ed25519(key, b"conveyor/v1/sig\\n" + record_hash_bytes), base64."""
        return _b64(self._key.sign(_signed_message(record_hash_hex)).signature)


def sign_record_hash(key: SigningKey, record_hash_hex: str) -> str:
    return key.sign(record_hash_hex)


def verify_record_hash(public_key_b64: str, record_hash_hex: str, signature_b64: str) -> bool:
    """True if `signature_b64` is a valid signature of the record hash under the key.

    Malformed inputs (bad base64, wrong lengths, bad hex) return False rather than raising:
    the verifier treats them as "not a valid signature".
    """
    try:
        verify_key = VerifyKey(_unb64(public_key_b64, 32))
        verify_key.verify(_signed_message(record_hash_hex), _unb64(signature_b64, 64))
    except (BadSignatureError, ValueError):
        return False
    return True
