"""Canonical-bytes encoding for signed Yutha messages.

A "canonical" encoding is one that two independent implementations of
the spec, in any language, MUST agree on bytewise. Yutha uses it for two
things and two things only:

  1. **Content addressing.** The receipt-id, capability-id, and
     passport-id of a message are SHA-256 of its canonical bytes.
  2. **Signing.** The actor / issuer / sender signs the canonical bytes
     of the message with its signature field cleared. Receivers
     recompute the canonical bytes and verify against the signature.

For the wire format itself we lean on protobuf with strict knobs:

  - **Tag-sorted field order.** Protobuf doesn't promise a serialization
    order by default. The Python runtime exposes
    ``SerializeToString(deterministic=True)``, which writes fields in
    tag-numeric order. That matches what prost does by default in Rust
    and what ``proto.MarshalOptions{Deterministic: true}.Marshal(...)``
    does in Go.
  - **Sorted map keys.** The Rust side encodes map fields as
    ``BTreeMap`` (via ``btree_map(["."])`` in ``yutha-proto``'s
    ``build.rs``). Python's ``deterministic=True`` serialization sorts
    map keys by their wire-encoded form, which is byte-equivalent for
    ASCII keys. That covers every map in the current spec.
  - **No unknown fields.** Generated messages from our ``.proto`` set
    don't carry unknown fields when constructed in-process, so we don't
    need to scrub them.

Cross-language conformance is verified by the ``test_vectors.py`` tests
under ``/sdks/python/tests/``, which load the JSON fixtures from
``/spec/vectors/`` and assert that the Python side produces the same
hex bytes the Rust side committed.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from yutha.crypto import Hash, content_address


@runtime_checkable
class _ProtoMessage(Protocol):
    """Structural protocol matching the protobuf-generated message
    surface we actually use. Avoids depending on a concrete base class
    (the protobuf runtime's `Message` is defined under
    ``google.protobuf.message`` but importing it directly is fragile
    across protobuf 5/6).
    """

    # `deterministic` is keyword-only in the protobuf-generated stub
    # signature (`def SerializeToString(self, *, deterministic: ...)`).
    # The protocol has to match keyword-only-ness or proto-generated
    # types fail the structural-subtype check — mypy specifically
    # rejects the looser "positional-or-keyword" form here.
    def SerializeToString(self, *, deterministic: bool = False) -> bytes: ...


def canonical_bytes(message: _ProtoMessage) -> bytes:
    """Canonical wire encoding of a protobuf message.

    The message MUST already have its signature / extensions / seal
    fields cleared if the canonical form requires it — this function is
    the *encoding* step, not the *normalization* step. The signed-type
    Pydantic models (``Passport``, ``Envelope``, ``Capability``,
    ``Receipt``) each have a ``.canonical_bytes()`` method that does
    the normalization first.

    Why we pass through here at all (vs. inlining
    ``msg.SerializeToString(deterministic=True)`` at every call site):

      - Centralizes the encoding rule in one place. If protobuf
        introduces a new deterministic-encoding knob, we change it
        here, not at twenty call sites.
      - Lets us add validation later (e.g. reject messages with
        non-empty signature fields when computing canonical bytes for
        signing) without breaking callers.
    """
    return message.SerializeToString(deterministic=True)


def content_address_of(message: _ProtoMessage) -> Hash:
    """One-stop content-address computation: canonical-encode then
    SHA-256. The receipt/capability/passport ID is exactly this hash."""
    return content_address(canonical_bytes(message))


__all__ = [
    "canonical_bytes",
    "content_address_of",
]
