"""Async gRPC channel construction with TLS / mTLS knobs that mirror
the Rust control-plane's flags.

The Yutha control plane (Rust binary ``yutha``) accepts three TLS
modes, controlled by its CLI flags:

  - ``--grpc-addr`` alone → plaintext (loopback dev default).
  - ``--tls-cert`` + ``--tls-key`` → server-side TLS.
  - ``--tls-cert`` + ``--tls-key`` + ``--client-ca`` → mTLS (server
    still requires the bearer token; the cert is an additional layer).

This module exposes :func:`make_channel` that takes the same knobs on
the client side and returns a connected ``grpc.aio.Channel`` with the
bearer-token interceptors already wired in. Callers don't need to know
about grpc.aio's credentials API.
"""

from __future__ import annotations

from pathlib import Path

import grpc

from yutha.auth import BearerSession, OperatorBearerSession, make_interceptors


def _read(path: str | Path | None) -> bytes | None:
    if path is None:
        return None
    return Path(path).read_bytes()


def make_channel(
    address: str,
    session: BearerSession | OperatorBearerSession,
    *,
    tls_root_ca: str | Path | bytes | None = None,
    client_cert: str | Path | bytes | None = None,
    client_key: str | Path | bytes | None = None,
) -> grpc.aio.Channel:
    """Construct a connected ``grpc.aio.Channel`` with bearer-token
    auth interceptors.

    Modes (mirror of the Rust server flags):

      - Both ``client_cert`` and ``client_key`` set → mTLS. The
        ``tls_root_ca`` argument is the CA bundle that verifies the
        server cert; on systems with a trusted root store, pass
        ``None`` and ``grpc`` will fall back to the system roots.
      - ``tls_root_ca`` set, ``client_cert`` / ``client_key`` unset →
        one-way TLS (server cert verified, no client cert presented).
      - All three None → plaintext (loopback dev default; do NOT use
        across hosts).

    Bytes can be passed directly (useful in tests / when secrets come
    from KMS) or as file paths (the more common operator-supplied
    case).

    The returned channel is *open*; the caller MUST ``await
    channel.close()`` when done.
    """
    root_ca = (
        _read(tls_root_ca)
        if not isinstance(tls_root_ca, (bytes, bytearray))
        else bytes(tls_root_ca)
    )
    cert = (
        _read(client_cert)
        if not isinstance(client_cert, (bytes, bytearray))
        else bytes(client_cert)
    )
    key = _read(client_key) if not isinstance(client_key, (bytes, bytearray)) else bytes(client_key)

    if (cert is None) != (key is None):
        raise ValueError(
            "client_cert and client_key must be set together (or both omitted); "
            "got one without the other"
        )

    interceptors = make_interceptors(session)

    if root_ca is None and cert is None:
        # Plaintext loopback.
        return grpc.aio.insecure_channel(address, interceptors=list(interceptors))

    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_ca,
        private_key=key,
        certificate_chain=cert,
    )
    return grpc.aio.secure_channel(address, credentials, interceptors=list(interceptors))


__all__ = ["make_channel"]
