"""Unit tests for ``yutha.crypto`` and ``yutha.identity``."""

from __future__ import annotations

import pytest

import yutha


def test_ed25519_sign_and_verify_roundtrip() -> None:
    key = yutha.SigningKey.generate()
    msg = b"hello yutha"
    sig = key.sign_message(msg)
    yutha.verify(key.public_key(), msg, sig)  # raises on failure


def test_verify_rejects_tampered_message() -> None:
    key = yutha.SigningKey.generate()
    sig = key.sign_message(b"original message")
    with pytest.raises(yutha.VerificationFailed):
        yutha.verify(key.public_key(), b"tampered message", sig)


def test_verify_rejects_wrong_key() -> None:
    k1 = yutha.SigningKey.generate()
    k2 = yutha.SigningKey.generate()
    sig = k1.sign_message(b"msg")
    with pytest.raises(yutha.VerificationFailed):
        yutha.verify(k2.public_key(), b"msg", sig)


def test_deterministic_signing_key_is_stable() -> None:
    a = yutha.deterministic_signing_key(b"yutha-test-fixture")
    b = yutha.deterministic_signing_key(b"yutha-test-fixture")
    assert a.public_key_bytes() == b.public_key_bytes()
    assert a.seed_bytes() == b.seed_bytes()


def test_signature_fingerprint_matches_sha256_of_public_key() -> None:
    key = yutha.SigningKey.generate()
    sig = key.sign_message(b"any message")
    assert sig.key_fingerprint == yutha.sha256(key.public_key_bytes())


def test_agent_id_round_trips_through_proto() -> None:
    a = yutha.AgentId.new()
    p = a.to_proto()
    b = yutha.AgentId.from_proto(p)
    assert a == b


def test_agent_id_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        yutha.AgentId(value=b"\x00" * 15)


def test_hash_validates_digest_length() -> None:
    # SHA-256 digest must be 32 bytes.
    yutha.Hash(algorithm=yutha.HashAlgorithm.SHA256, digest=b"\x00" * 32)
    with pytest.raises(ValueError):
        yutha.Hash(algorithm=yutha.HashAlgorithm.SHA256, digest=b"\x00" * 31)


def test_content_address_matches_sha256() -> None:
    payload = b"some canonical bytes"
    h = yutha.content_address(payload)
    assert h.algorithm == yutha.HashAlgorithm.SHA256
    assert h.digest == yutha.sha256(payload)


def test_timestamp_now_produces_valid_rfc3339() -> None:
    t = yutha.Timestamp.now()
    assert "T" in t.wall_clock
    assert t.wall_clock.endswith("Z")
    assert t.monotonic_ns > 0


def test_timestamp_rejects_garbage_wall_clock() -> None:
    with pytest.raises(ValueError):
        yutha.Timestamp(wall_clock="not a timestamp", monotonic_ns=1)


def test_signature_rejects_reserved_pq() -> None:
    with pytest.raises(ValueError):
        yutha.Signature(
            algorithm=yutha.SignatureAlgorithm.RESERVED_PQ,
            value=b"\x00" * 64,
            key_fingerprint=b"\x00" * 32,
        )
