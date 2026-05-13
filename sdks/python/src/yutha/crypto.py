"""Ed25519 + SHA-256 wrappers — Python mirror of the Rust
``yutha-crypto`` crate.

The substrate uses Ed25519 for every signature path (passports,
envelopes, receipts, capabilities, bearer tokens) and SHA-256 for every
content-address. This module wraps
``cryptography.hazmat.primitives.asymmetric.ed25519`` and ``hashlib`` to
give the SDK an API surface that matches the Rust side:

  - ``SigningKey.generate()`` — fresh keypair.
  - ``SigningKey.from_bytes(b)`` — load from 32 raw seed bytes.
  - ``signing_key.public_key()`` → ``PublicKey`` (the ergonomic Yutha
    type from ``yutha.identity``).
  - ``signing_key.sign(message)`` → ``Signature``.
  - ``verify(public_key, message, signature)`` — raises
    ``InvalidSignature`` on mismatch.
  - ``sha256(b)`` / ``content_address(canonical_bytes)`` — Hash helpers.
  - ``fingerprint_public_key(pk_bytes)`` — SHA-256 of the public-key
    bytes; matches the Rust ``yutha_crypto::fingerprint_public_key``
    used for ``Signature.key_fingerprint``.

The deliberate naming overlap with the Rust crate (``SigningKey``,
``PublicKey``, ``sign_message``) is so cross-referencing between the
two implementations stays obvious.
"""

from __future__ import annotations

import hashlib
import os
from typing import ClassVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from yutha.identity import Hash, HashAlgorithm, PublicKey, Signature, SignatureAlgorithm

# =============================================================================
# Errors
# =============================================================================


class CryptoError(Exception):
    """Base class for Yutha crypto errors. Mirrors Rust ``CryptoError``."""


class VerificationFailed(CryptoError):
    """Signature verification failed — bad bytes, wrong key, tampered
    message."""


# =============================================================================
# SHA-256 helpers
# =============================================================================


def sha256(data: bytes) -> bytes:
    """Raw 32-byte SHA-256 digest."""
    return hashlib.sha256(data).digest()


def content_address(canonical_bytes: bytes) -> Hash:
    """Content-address a canonical byte sequence. SHA-256 by spec."""
    return Hash(algorithm=HashAlgorithm.SHA256, digest=sha256(canonical_bytes))


def fingerprint_public_key(public_key_bytes: bytes) -> bytes:
    """SHA-256 of the public-key bytes — what goes into the
    ``Signature.key_fingerprint`` field.

    Mirrors ``yutha_crypto::fingerprint_public_key`` on the Rust side.
    Always 32 bytes regardless of the underlying public-key algorithm
    (Ed25519 keys are themselves 32 bytes, but the fingerprint is
    algorithm-agnostic).
    """
    return sha256(public_key_bytes)


# =============================================================================
# Ed25519 signing key
# =============================================================================


class SigningKey:
    """A private signing key. Treat as a secret.

    Mirrors Rust's ``yutha_crypto::SigningKey``. ``Ed25519PrivateKey``
    from ``cryptography`` is wrapped rather than subclassed because
    that class isn't designed for subclassing.
    """

    ALGORITHM: ClassVar[SignatureAlgorithm] = SignatureAlgorithm.ED25519

    def __init__(self, inner: ed25519.Ed25519PrivateKey) -> None:
        self._inner = inner

    @classmethod
    def generate(cls) -> SigningKey:
        """Fresh keypair from the OS CSPRNG."""
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_seed_bytes(cls, seed: bytes) -> SigningKey:
        """Construct from 32 raw seed bytes.

        These are the seed bytes (Ed25519 expands them internally),
        not a PKCS#8-encoded private key. Use ``generate()`` unless you
        have a specific reason to be loading from a fixed seed (test
        vectors, deterministic test harnesses).
        """
        if len(seed) != 32:
            raise CryptoError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    def public_key(self) -> PublicKey:
        """The matching public key as a Yutha ``PublicKey``."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        raw = self._inner.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        return PublicKey(algorithm=self.ALGORITHM, value=raw)

    def public_key_bytes(self) -> bytes:
        """The matching public key as raw 32 bytes."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return self._inner.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    def sign_message(self, message: bytes) -> Signature:
        """Produce a Yutha ``Signature`` over ``message``.

        The signature carries the public key's fingerprint so receivers
        can look up the key in a registry without having to ship the
        full public key inline.
        """
        sig_bytes = self._inner.sign(message)
        return Signature(
            algorithm=self.ALGORITHM,
            value=sig_bytes,
            key_fingerprint=fingerprint_public_key(self.public_key_bytes()),
        )

    def seed_bytes(self) -> bytes:
        """The 32-byte seed of this key. Treat as secret."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        # Raw is the seed; PKCS8 would wrap it.
        return self._inner.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )

    def __repr__(self) -> str:
        return "SigningKey(<redacted>)"


# =============================================================================
# Verify
# =============================================================================


def verify(public_key: PublicKey, message: bytes, signature: Signature) -> None:
    """Verify ``signature`` over ``message`` against ``public_key``.

    Raises ``VerificationFailed`` on any mismatch. Does NOT verify
    ``signature.key_fingerprint`` against ``public_key`` — that's a
    higher-layer (resolver) responsibility. This function only checks
    the cryptographic signature itself.
    """
    if public_key.algorithm != SignatureAlgorithm.ED25519:
        raise CryptoError(f"unsupported public-key algorithm: {public_key.algorithm}")
    if signature.algorithm != SignatureAlgorithm.ED25519:
        raise CryptoError(f"unsupported signature algorithm: {signature.algorithm}")

    pk_inner = ed25519.Ed25519PublicKey.from_public_bytes(public_key.value)
    try:
        pk_inner.verify(signature.value, message)
    except InvalidSignature as e:
        raise VerificationFailed("Ed25519 signature verification failed") from e


# =============================================================================
# Test-utility — deterministic key from a fixed seed
# =============================================================================


def deterministic_signing_key(label: bytes) -> SigningKey:
    """Derive a signing key from a stable label (SHA-256 of the label
    used as the Ed25519 seed). Useful for tests and for fixture
    construction; never use in production.
    """
    seed = sha256(label)
    return SigningKey.from_seed_bytes(seed)


__all__ = [
    "SigningKey",
    "verify",
    "sha256",
    "content_address",
    "fingerprint_public_key",
    "deterministic_signing_key",
    "CryptoError",
    "VerificationFailed",
    "InvalidSignature",
    # Re-exported for convenience.
    "PublicKey",
    "Signature",
    "Hash",
]


# Random seed helper kept here so callers don't have to ``import os``.
def random_seed() -> bytes:
    """32 cryptographically-random bytes; suitable as an Ed25519 seed."""
    return os.urandom(32)
