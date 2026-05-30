"""Ed25519 + SHA-256 wrappers — Python mirror of the Rust
``yutha-crypto`` + ``yutha-signer`` crates.

The substrate uses Ed25519 for every signature path (passports,
envelopes, receipts, capabilities, bearer tokens) and SHA-256 for every
content-address. This module wraps
``cryptography.hazmat.primitives.asymmetric.ed25519`` and ``hashlib`` to
give the SDK an API surface that matches the Rust side:

  - :class:`Signer` — the *async* signing Protocol every higher-level
    Yutha API takes. Mirrors the Rust ``yutha_signer::Signer`` trait
    (RFC 0015): two methods, ``public_key()`` and ``sign_message()``,
    nothing else. Implementations may hold the private bytes in process
    (:class:`InProcessSigner`) or behind a network boundary (cloud KMS,
    Vault transit — those live in separate optional packages).
  - :class:`InProcessSigner` — the zero-dependency default. Wraps a
    :class:`SigningKey` and presents the async Signer surface.
  - :class:`SigningKey` — raw Ed25519 keypair. Lives at a lower layer:
    operator tooling that needs to mint bearer tokens offline (without
    spinning up a custody backend) still constructs one of these
    directly, and ``InProcessSigner`` wraps one internally.
  - ``verify(public_key, message, signature)`` — raises
    ``InvalidSignature`` on mismatch.
  - ``sha256(b)`` / ``content_address(canonical_bytes)`` — Hash helpers.
  - ``fingerprint_public_key(pk_bytes)`` — SHA-256 of the public-key
    bytes; matches the Rust ``yutha_crypto::fingerprint_public_key``
    used for ``Signature.key_fingerprint``.

The deliberate naming overlap with the Rust crate (``SigningKey``,
``Signer``, ``InProcessSigner``, ``PublicKey``, ``sign_message``) is so
cross-referencing between the two implementations stays obvious.

Two invariants the :class:`Signer` Protocol enforces (mirroring RFC
0015 §3.1):

1. **No raw-key export.** The Protocol exposes ``public_key`` and
   ``sign_message``; nothing else. Implementations may not return
   private bytes. (``InProcessSigner.signing_key`` does exist as an
   inherent attribute for callers that *do* hold the in-process
   variant — e.g. operator tooling — but the Protocol shape forbids
   reaching for it through a polymorphic ``Signer`` reference.)
2. **Algorithm pinned to Ed25519.** The returned :class:`Signature`
   MUST verify under :meth:`Signer.public_key` per RFC 8032.
"""

from __future__ import annotations

import hashlib
import os
from typing import ClassVar, Protocol, runtime_checkable

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
# Signer Protocol + in-process default
# =============================================================================


@runtime_checkable
class Signer(Protocol):
    """The signing-key custody Protocol every Yutha API takes.

    Mirrors the Rust ``yutha_signer::Signer`` trait (RFC 0015).
    Implementations may hold the private bytes in process
    (:class:`InProcessSigner`) or expose only a handle to an external
    custody backend (cloud KMS, Vault transit — those live in separate
    optional packages, not here).

    The two methods are deliberately the *entire* surface:

      * :meth:`public_key` is sync and infallible by contract. Callers
        may invoke it freely (the Pydantic models call it during
        ``sign(...)`` to cross-check that the signer matches the
        passport's ``agent_public_key`` field).
      * :meth:`sign_message` is ``async`` because cloud-KMS-backed
        signers are network-bound. For the in-process default the
        future is immediately ready and the overhead is well under
        100 µs per call.

    Both methods MUST be implemented; ``@runtime_checkable`` so callers
    can ``isinstance(x, Signer)`` to validate adapter inputs.
    """

    def public_key(self) -> PublicKey:
        """Return the public counterpart of the signing capability.

        Sync and infallible. Must return the same :class:`PublicKey`
        across calls (no key rotation through this interface; rotation
        happens via :meth:`AdmissionAPI.rotate_key` and re-binding a
        fresh signer)."""
        ...

    async def sign_message(self, message: bytes) -> Signature:
        """Produce an Ed25519 signature over ``message``.

        The returned :class:`Signature` MUST verify under
        :meth:`public_key` per RFC 8032. The
        ``Signature.key_fingerprint`` field carries the SHA-256 of the
        public-key bytes so receivers can correlate without re-shipping
        the full public key inline."""
        ...


class InProcessSigner:
    """The zero-dependency default :class:`Signer` implementation.

    Wraps a :class:`SigningKey` byte-for-byte. What hobby swarms and
    development workflows run today; the SDK's signing path looks
    identical in shape to what it would with a cloud-KMS-backed signer,
    just with the private key bytes living in process memory rather than
    behind a network boundary.

    Construct via :meth:`from_seed_bytes` (deterministic from a 32-byte
    seed — vector tests + fixed-key fixtures use this) or
    :meth:`generate` (fresh from the OS CSPRNG).
    """

    ALGORITHM: ClassVar[SignatureAlgorithm] = SignatureAlgorithm.ED25519

    def __init__(self, signing_key: SigningKey) -> None:
        self._signing_key = signing_key
        self._public_key = signing_key.public_key()

    # -------------------------------------------------------------------------
    # Constructors
    # -------------------------------------------------------------------------

    @classmethod
    def from_seed_bytes(cls, seed: bytes) -> InProcessSigner:
        """Construct from a 32-byte Ed25519 seed. Mirrors Rust's
        ``InProcessSigner::from_bytes``."""
        return cls(SigningKey.from_seed_bytes(seed))

    @classmethod
    def generate(cls) -> InProcessSigner:
        """Generate a fresh keypair from the OS CSPRNG. Test / demo
        convenience."""
        return cls(SigningKey.generate())

    @classmethod
    def from_signing_key(cls, signing_key: SigningKey) -> InProcessSigner:
        """Wrap an existing :class:`SigningKey`.

        Used by operator tooling that has already constructed a raw
        ``SigningKey`` (e.g. ``yutha-ops`` shells out to derive the
        operator seed) and needs to lift it into the Signer Protocol
        for ``BearerSession`` / ``OperatorBearerSession``. Long-term
        callers should prefer :meth:`from_seed_bytes` directly."""
        return cls(signing_key)

    # -------------------------------------------------------------------------
    # Signer Protocol
    # -------------------------------------------------------------------------

    def public_key(self) -> PublicKey:
        """Cached public key of this signing capability."""
        return self._public_key

    async def sign_message(self, message: bytes) -> Signature:
        """Produce a Yutha :class:`Signature` over ``message``.

        Ed25519 signing is CPU-bound and fast (~50 µs); we sign on the
        calling task's worker rather than ``run_in_executor``. The
        ``async`` shape matches the cloud-KMS path so the call site
        looks the same regardless of where the key lives."""
        return self._signing_key.sign_message(message)

    # -------------------------------------------------------------------------
    # Escape hatch — exposed for InProcessSigner specifically, NOT for
    # the polymorphic Signer Protocol.
    # -------------------------------------------------------------------------

    @property
    def signing_key(self) -> SigningKey:
        """The wrapped :class:`SigningKey`. Available for tooling that
        needs raw seed access (e.g. exporting a key for an offline
        backup, computing the seed bytes for a CLI flag). NOT part of
        the :class:`Signer` Protocol — polymorphic ``Signer`` references
        cannot reach this; callers must hold the concrete
        ``InProcessSigner`` type."""
        return self._signing_key

    def __repr__(self) -> str:
        return "InProcessSigner(<redacted>)"


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
    "Signer",
    "InProcessSigner",
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
