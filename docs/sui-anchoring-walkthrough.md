# Anchoring Yutha receipts on Sui

A 30-minute walkthrough for the operator who wants to prove out
RFC 0014's verifiability Layer 1 against a real Sui chain. By the
end you'll have:

- A localnet validator running with the `receipt_anchor` Move package
  published under your operator address.
- A `SwarmAnchor` shared object owned by the swarm, bound to a
  sealer Ed25519 public key you control.
- A pass of the `yutha-backend-sui-anchor` integration test against
  that chain, demonstrating the full Rust sealer → PTB → on-chain
  signature verify → `AnchorCommitted` event path.

**What you get for free.** The `yutha-receipt::LocalSealer` already
produces the canonical preimage byte-for-byte; the
`yutha-backend-sui-anchor` crate composes that sealer with a real Sui
RPC client, builds the PTB, signs the transaction, and waits for
checkpoint inclusion. The Move package on-chain reconstructs the same
preimage, verifies the Ed25519 signature, enforces the monotonic
ns-range + histogram sort/length invariants, and emits an
`AnchorCommitted` event for every successful commit.

**What you write.** The operator's sealer key (Ed25519, bound to one
`SwarmAnchor` per swarm), the choice of Sui network (localnet for this
walkthrough; testnet / mainnet in production), and — once H6 wires
the `AnchorDriver` into the control-plane binary — the CLI flags that
plug your published `package_id` and per-swarm `SwarmAnchor` object id
into the running server. Until then, the cadence-loop driver is
exercised through the integration test in this walkthrough.

If you haven't operated a Yutha swarm before, read the
[constitution operator walkthrough](operator-walkthrough.md) first —
it covers the bootstrap-seed model, the operator credential, and the
gRPC server flags this doc assumes you're already comfortable with.

---

## Prerequisites

You need five things on hand before any of the commands work.

**1. Rust ≥ 1.85.** The `sui-rust-sdk` crates we depend on are
edition-2024, which requires this. Check with `rustc --version`; if
older, `rustup update stable`.

**2. The `sui` CLI.** Install via the
[Sui install docs](https://docs.sui.io/guides/developer/getting-started/sui-install)
or `brew install sui`. The walkthrough was written against `sui
1.41+`; if your CLI is older the `keytool generate` JSON output may
differ (older versions emitted `suiPrivateKey` directly; current ones
require a separate `keytool export` step — both paths are covered
below).

**3. A local clone of `sui-rust-sdk` next to this repo.** The Yutha
workspace pins to a path dep at `../sui-rust-sdk/` because the
`bech32` feature on `sui-crypto` (needed for the canonical
`suiprivkey1…` keystore format) lands in the trunk *after* the
crates.io 0.3.0 release. From the repo root:

```bash
cd ..
git clone https://github.com/MystenLabs/sui-rust-sdk
cd Yutha
```

When a tagged release with the `bech32` feature lands on crates.io,
the workspace `Cargo.toml` can switch from a path dep back to a
version dep and this step goes away.

**4. The Yutha workspace built.** From the repo root:

```bash
cargo build -p yutha-backend-sui-anchor
```

**5. `jq` and `openssl` for the shell helpers.** `brew install jq` if
needed.

---

## Step 1 — Start localnet

In a terminal you'll keep open for the rest of the walkthrough:

```bash
sui start --force-regenesis --with-faucet
```

`--force-regenesis` discards any prior localnet state (you'll
regenerate it on every walkthrough run). `--with-faucet` runs the
local faucet on port 9123 so the next step can drip gas without
external setup. The validator listens on `http://127.0.0.1:9000` for
both gRPC and JSON-RPC; the Rust SDK speaks gRPC.

Wait until you see `Sui Node started!` in the logs.

---

## Step 2 — Point the CLI at localnet

In a second terminal:

```bash
sui client new-env --alias localnet --rpc http://127.0.0.1:9000 2>/dev/null || true
sui client switch --env localnet
sui client active-env  # should print: localnet
```

The first line is idempotent — it'll fail-and-ignore if you already
have a `localnet` env from a prior run.

---

## Step 3 — Generate the sealer key

The sealer key is what signs the canonical preimage off-chain. The
matching public key is what the on-chain `ed25519_verify` call
checks against. They have to be the same key or every commit aborts
with `ESealerKeyMismatch`.

The current `sui keytool` flow takes three steps: generate, import,
export. Older versions could do it in one; current ones split the
private-key export out for safety.

```bash
# 3a. Generate (prints details to stdout; does NOT add to keystore
#     in current sui versions, despite older docs).
SEALER_OUT=$(sui keytool generate ed25519 --json)
SEALER_ADDR=$(echo "$SEALER_OUT" | jq -r '.suiAddress')
SEALER_MNEMONIC=$(echo "$SEALER_OUT" | jq -r '.mnemonic')
SEALER_PUBKEY_B64=$(echo "$SEALER_OUT" | jq -r '.publicBase64Key')

# 3b. Strip the leading ed25519 scheme-flag byte (0x00) from
#     publicBase64Key to recover the raw 32-byte pubkey that
#     create_swarm_anchor expects on-chain.
SEALER_PUBKEY_HEX=0x$(echo "$SEALER_PUBKEY_B64" | base64 -d | tail -c 32 | xxd -p -c 64)

# 3c. Import the mnemonic so the CLI keystore can sign with this
#     address.
sui keytool import "$SEALER_MNEMONIC" ed25519 --json >/dev/null

# 3d. Export the bech32 suiprivkey1… string. The Yutha sealer reads
#     this from a file at runtime via
#     yutha-backend-sui-anchor::keystore::load_sealer_key_from_file.
SEALER_PRIVKEY=$(sui keytool export --key-identity "$SEALER_ADDR" --json | jq -r '.exportedPrivateKey')

mkdir -p ~/.yutha
echo -n "$SEALER_PRIVKEY" > ~/.yutha/sealer.key
chmod 600 ~/.yutha/sealer.key

# 3e. Make this the CLI's active signer so publish / call uses it.
sui client switch --address "$SEALER_ADDR"

echo "----- sealer setup -----"
echo "addr:    $SEALER_ADDR"
echo "pubkey:  $SEALER_PUBKEY_HEX"
echo "privkey: $(head -c 12 ~/.yutha/sealer.key)... (saved to ~/.yutha/sealer.key)"
```

**Sanity checks before continuing:**

- `$SEALER_PUBKEY_HEX` must be `0x` plus exactly 64 hex characters.
  Verify: `echo -n "$SEALER_PUBKEY_HEX" | wc -c` prints `66`.
- `$SEALER_PRIVKEY` must start with `suiprivkey1`. Verify:
  `head -c 12 ~/.yutha/sealer.key` prints `suiprivkey1`.

If either of those is wrong, re-run step 3 from the top. The most
common cause of subtle failures downstream is a malformed pubkey hex
(usually because the base64 strip in 3b ran against a different
field).

---

## Step 4 — Fund the sealer

```bash
sui client faucet
sleep 8
sui client gas
```

`sui client gas` should list at least one coin owned by
`$SEALER_ADDR` with a non-zero balance. If empty, retry: `sui client
faucet; sleep 8; sui client gas`.

---

## Step 5 — Publish the `receipt_anchor` Move package

The Move package at `contracts/sui/receipt_anchor/` is what enforces
the anchoring rules on-chain. Each operator publishes their own copy
(RFC 0014's operator-owned model — there's no canonical mainnet
deployment).

```bash
cd /Users/abhinavgarg/Documents/Claude/Yutha/contracts/sui/receipt_anchor

# Clean up any stale chain-id pinning from a prior --force-regenesis.
rm -f Pub.localnet.toml

# --build-env testnet works for localnet too — Sui's per-network
# framework versions are forward-compatible at this layer, and
# Move.toml doesn't define a localnet environment.
PUBLISH_OUT=$(sui client test-publish --build-env testnet --json)
PACKAGE_ID=$(echo "$PUBLISH_OUT" | jq -r '.objectChanges[] | select(.type=="published") | .packageId')

echo "package_id: $PACKAGE_ID"
test -n "$PACKAGE_ID" && [ "$PACKAGE_ID" != "null" ] || echo "PUBLISH FAILED"
```

Sanity: `$PACKAGE_ID` should be a `0x…` 64-hex-char string.

---

## Step 6 — Create the `SwarmAnchor`

One `SwarmAnchor` per swarm. Its on-chain `sealer_pubkey` field is
checked on every `commit_batch`; if it doesn't match the off-chain
sealing key's pubkey, the commit aborts.

The `yutha-backend-sui-anchor` integration test fixture uses
`swarm_id = [0x42; 16]`. If you're running this walkthrough purely to
verify the smoke test passes, use that exact value. If you're
adapting for a real swarm, substitute your swarm's 16-byte UUID.

```bash
SWARM_ID_HEX=0x42424242424242424242424242424242

CREATE_OUT=$(sui client call \
  --package "$PACKAGE_ID" \
  --module receipt_anchor \
  --function create_swarm_anchor \
  --args "$SWARM_ID_HEX" "$SEALER_PUBKEY_HEX" 0x6 \
  --gas-budget 100000000 \
  --json)

SWARM_ANCHOR_ID=$(echo "$CREATE_OUT" | jq -r \
  '.objectChanges[] | select(.type=="created" and (.objectType | test("SwarmAnchor"))) | .objectId')

echo "swarm_anchor_id: $SWARM_ANCHOR_ID"
```

The `0x6` argument is the canonical Sui system clock (stable across
all Sui networks — `create_swarm_anchor` records the `created_at_ms`
timestamp from it).

**Sanity:** read back the object and confirm the on-chain
`sealer_pubkey` matches the off-chain `$SEALER_PUBKEY_HEX`:

```bash
sui client object "$SWARM_ANCHOR_ID" --json \
  | jq '.data.content.fields | {swarm_id, sealer_pubkey, batch_count, last_ns_range_end}'
```

If the on-chain `sealer_pubkey` bytes don't decode to the same hex as
`$SEALER_PUBKEY_HEX`, **stop and re-create the anchor** — `commit_batch`
will abort with `ESealerKeyMismatch` (code 9) on every attempt until
they match.

---

## Step 7 — Run the integration test

```bash
cd /Users/abhinavgarg/Documents/Claude/Yutha

YUTHA_SUI_RPC_URL=http://127.0.0.1:9000 \
YUTHA_SUI_PACKAGE_ID="$PACKAGE_ID" \
YUTHA_SUI_SWARM_ANCHOR_ID="$SWARM_ANCHOR_ID" \
YUTHA_SUI_SEALER_KEY="$HOME/.yutha/sealer.key" \
RUST_LOG=yutha_backend_sui_anchor=debug,sui_rpc=info \
  cargo test -p yutha-backend-sui-anchor --test localnet -- --nocapture
```

Expected output (the receipt digests and tx hashes will differ each
run):

```
[sealer_commits_batch_to_localnet] pre-commit anchor state: batch_count=0, last_ns_range_end=0
[sealer_commits_batch_to_localnet] sealed batch_root=<64 hex> commit_tx=<64 hex>
[sealer_commits_batch_to_localnet] post-commit anchor state: batch_count=1, last_ns_range_end=200
test sealer_commits_batch_to_localnet ... ok
```

At this point you've proven:

1. The Rust sealer constructs the canonical preimage that matches
   what the Move package reconstructs on-chain (otherwise
   `ed25519_verify` would have failed).
2. The PTB encoding round-trips correctly through `bcs` +
   `sui-transaction-builder` + `commit_batch_from_arrays` (otherwise
   the transaction would have aborted on argument shape).
3. The `SwarmAnchor` state advances monotonically and the
   `commitment_id` returned by the sealer matches the Sui tx digest
   (verified by `read_anchor_state` before/after).

---

## Troubleshooting

The four most common failure modes, in rough order of how often each
bit us during initial development:

**Move abort code 9 (`ESealerKeyMismatch`).** The on-chain
`sealer_pubkey` doesn't match the off-chain key's pubkey. Check the
two values explicitly:

```bash
echo "off-chain:" "$SEALER_PUBKEY_HEX"
sui client object "$SWARM_ANCHOR_ID" --json \
  | jq -r '.data.content.fields.sealer_pubkey | map(.) | "0x" + (map(. | tostring) | join(","))'
```

(The second command formats the on-chain bytes as a Move-style array;
compare element by element with `$SEALER_PUBKEY_HEX`.)

If they don't match, you almost certainly regenerated the key
between steps 3 and 6. Re-run step 6 with the *current* key's pubkey.

**`Could not determine the correct dependencies to use for localnet`
on `sui move build` or `test-publish`.** `Move.toml` doesn't declare
a `localnet` environment. Use `--build-env testnet` — the framework
version is the same.

**`Ephemeral publication file ... has chain-id X; it cannot be used
to publish to chain Y`.** `sui client test-publish` caches the
chain-id of the last localnet it published to in
`contracts/sui/receipt_anchor/Pub.localnet.toml`. Every
`--force-regenesis` produces a new chain-id, invalidating that cache.
`rm Pub.localnet.toml` and retry. The file is `.gitignore`d.

**`Cannot find gas coin for signer address 0x… with amount sufficient
for the required gas budget`.** The CLI's active signer isn't the
funded sealer. Run `sui client active-address` — if it doesn't print
`$SEALER_ADDR`, run `sui client switch --address "$SEALER_ADDR"` and
retry the failing command.

**Move abort code 5 (`ENsRangeNotMonotonic`).** You're re-running the
integration test against an anchor that's already seen one commit.
The test picks `base_ns = before.last_ns_range_end + 1000` so this
shouldn't happen across consecutive runs against the same anchor —
but if you've poked at the anchor by hand or restarted the validator
without re-creating the anchor, the off-chain test's monotonic-clock
fixtures may not advance fast enough. Either re-create the anchor
(step 6) or wait until enough wall-clock time has passed that the
test's monotonic baseline is above the on-chain watermark.

**Move abort code 4 (`ENsRangeInvalid`).** `ns_range_start >
ns_range_end`. Shouldn't ever fire from the test — would indicate a
bug in `compute_ns_range` in `yutha-receipt`.

**Move abort code 10 (`EHistogramNotSorted`).** The histogram entries
weren't in lex-ascending key order. The Rust sealer iterates a
`BTreeMap<String, u64>` to build the histogram, which guarantees the
right order. If this fires, something has gone wrong in the sealer's
`compute_histogram` path or in how `commit_batch_from_arrays`
materializes the on-chain `VecMap`. Look at the `histogram_keys` PTB
arg in the failing transaction's effects to see what order the bytes
arrived in.

---

## What's next

The H5 walkthrough above gets the Sui anchoring path running
end-to-end against a real chain, but the **`AnchorDriver` isn't yet
wired into the control-plane binary** — the cadence loop (poll the
receipt store for unsealed receipts, build batches when the count or
time threshold trips, submit `commit_batch` PTBs, advance the
watermark) only runs inside the integration test today. H6 will add
the control-plane CLI flags (`--anchor-sui-rpc-url`,
`--anchor-package-id`, `--anchor-swarm-anchor-id`,
`--anchor-sealer-key-file`, plus the cadence knobs) and the
`tokio::spawn(driver.run())` plumbing so an operator can stand up a
control plane with anchoring active from server start.

Until then, this walkthrough validates the substrate: if it passes
on your hardware against your chain, the production wiring is
plumbing, not logic.
