# yutha-backend-s3-blob

S3-compatible blob backend. Stores large receipt evidence payloads, bulk-export manifests, and any other oversized artifacts that don't belong in the relational store.

## Status

**Skeleton.** Cargo.toml in place; trait surface and default implementation pending.

## Design

The Postgres receipt store handles the structured rows and indices; this backend handles bytes. Typical flow:

1. A receipt with large evidence is written.
2. Evidence above a configurable size threshold (default 256 KiB) is stored in S3 keyed by content-address.
3. The Postgres row stores the evidence's content-address; the actual bytes live in S3.
4. Reads transparently fetch from S3 when needed.

This split keeps Postgres queries cheap and lets large evidence (transcripts, diffs, screenshots) coexist with the receipt fabric without bloating relational storage.

## S3-compatible meaning

Works with AWS S3, MinIO, Backblaze B2, Cloudflare R2, and any other S3-API-compatible blob store. The verifiable-tier counterpart for Walrus lives in `walrus-receipt`.

## Reference

- [`/crates/yutha-receipt/`](../../crates/yutha-receipt/)
- AWS SDK for Rust documentation.
