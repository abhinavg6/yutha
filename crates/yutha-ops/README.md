# yutha-ops

Operator CLI for the Yutha control plane. Five subcommands — three
over the gRPC surface, two pure-local:

Server-talking (operator- or agent-bearer auth):

* `activate <cedar-file> [--engine-config <yaml-file>]` — publish a
  constitution via `ConstitutionService.Activate` (operator-bearer).
* `grep <action_kind> [--limit N]` — query receipts by `action_kind`
  via `ReceiptService.Query` (agent-bearer).
* `revoke <agent_id> --reason <text> [--cascade]` — operator-revoke
  an agent via `AdmissionService.OperatorRevoke` (operator-bearer).

Pure-local (no server connection):

* `print-operator-pubkey` — derive the operator public key from
  `--seed` and print it as 64-char hex on stdout. Pipe straight into
  the control plane's `--operator-public-key` flag at startup.
* `compile <yaml-file>` — compile a plain-English YAML DSL document
  to Cedar policy source + engine-config YAML.

## Auth

All three commands derive their identity from a single 32-byte hex
seed (`--seed` or `YUTHA_BOOTSTRAP_SEED`). The derivation matches
the control-plane binary's `BootstrapIdentity::from_seed_hex` —
agent id from `sha256(seed || 0x01)`, swarm id from
`sha256(seed || 0x02)`, operator signing key from
`sha256(seed || 0x03)`. So whatever seed the operator handed to the
server can be re-used here without copying extra material around.

## Examples

```bash
export YUTHA_BOOTSTRAP_SEED=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Start the server with the same seed + the operator pubkey it
# derives from sha256(seed || 0x03).
cargo run -p yutha-control-plane -- \
    --admission-mode open \
    --operator-public-key "$(yutha-ops print-operator-pubkey)"

# Activate a constitution.
yutha-ops activate \
    spec/constitution/canonical-schemas/v1.1.0/examples/support-queue-refund-cap.cedar \
    --engine-config spec/constitution/canonical-schemas/v1.1.0/examples/support-queue-refund-cap.engine.yaml

# Query the audit log.
yutha-ops grep constitution.evaluate.deny --limit 10

# Revoke an agent.
yutha-ops revoke 019e3ce9-8d7d-70ec-9209-e34415ca9477 \
    --reason "scope-creep on PII access" --cascade
```

## Wire shape

The CLI mints bearer tokens the same way the Python SDK does:
prost-encode the `AgentBearerToken` / `OperatorBearerToken` proto
with the `signature` field cleared (canonical bytes), Ed25519-sign
those bytes, attach the signature to the proto, re-encode, hex-
encode for the wire. Attach as `authorization: bearer agent <hex>`
or `bearer operator <hex>` on the gRPC metadata.

## Limitations

* Plain-text gRPC only. TLS-protected servers should use the Python
  SDK (which supports `tls_root_ca` / client certs).
* No token caching — every invocation mints fresh credentials.
  Acceptable for human-driven ops use; embed the Python SDK if you
  need a long-running operator agent.
* `activate` only sends genesis constitutions (`parent_version`
  unset). Amendment publishing (with a real parent_version) lands in
  a future revision.
