//! Localnet integration test for the Sui-anchor backend.
//!
//! Skipped by default; runs when:
//!   - `YUTHA_SUI_RPC_URL` is set (e.g. `http://127.0.0.1:9000` for a
//!     local `sui-test-validator`).
//!   - `YUTHA_SUI_PACKAGE_ID` is set (the result of `sui client
//!     publish` against the Move package in
//!     `/contracts/sui/receipt_anchor/`).
//!   - `YUTHA_SUI_SWARM_ANCHOR_ID` is set (the shared-object id
//!     returned by calling `create_swarm_anchor` once after publish).
//!   - `YUTHA_SUI_SEALER_KEY` is set (path to a `suiprivkey1…` file
//!     for the registered sealer key).
//!
//! Setup script (run once on your localnet before the test):
//!
//! ```bash
//! cd contracts/sui/receipt_anchor
//! sui client switch --env localnet
//! sui client publish --gas-budget 100000000  # records PACKAGE_ID
//!
//! # Generate the sealer keypair.
//! sui keytool generate ed25519 --json > /tmp/sealer.json
//! # Extract the suiPrivateKey field into /tmp/sealer.key
//!
//! # Compute the matching public key (for create_swarm_anchor input):
//! # sui keytool import < ... > and inspect.
//!
//! # Create the SwarmAnchor:
//! sui client call --package PACKAGE_ID --module receipt_anchor \
//!     --function create_swarm_anchor --gas-budget 10000000 \
//!     --args [SWARM_ID_BYTES] [SEALER_PUBKEY_BYTES] 0x6
//! # records SWARM_ANCHOR_ID
//!
//! export YUTHA_SUI_RPC_URL=http://127.0.0.1:9000
//! export YUTHA_SUI_PACKAGE_ID=0x…
//! export YUTHA_SUI_SWARM_ANCHOR_ID=0x…
//! export YUTHA_SUI_SEALER_KEY=/tmp/sealer.key
//! cargo test -p yutha-backend-sui-anchor --test localnet -- --nocapture
//! ```

use std::sync::Arc;

use yutha_backend_sui_anchor::{
    load_sealer_key_from_file, RpcAnchorClient, SuiAnchorClient, SuiSealer,
};
use yutha_core::{AgentId, CausalRef, SpecVersion, SwarmId, Timestamp};
use yutha_receipt::{Evidence, Receipt, ReceiptBuilder, Sealer};

fn env_or_skip(test: &str, var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => {
            eprintln!("[{test}] {var} not set; skipping localnet test");
            None
        }
    }
}

fn fixture(monotonic_ns: u64, seed: u8) -> Receipt {
    ReceiptBuilder::new()
        .spec_version(SpecVersion::parse("1.0.0").unwrap())
        .swarm_id(SwarmId::from_bytes(&[0x42; 16]).unwrap())
        .actor({
            let mut b = [0u8; 16];
            b[0] = seed;
            AgentId::from_bytes(&b).unwrap()
        })
        .action_kind("envelope.send")
        .causal(CausalRef::default())
        .evidence(Evidence::new("k", "type.yutha.dev/v1/Bytes", vec![seed]))
        .constitution_version("1.0.0")
        .occurred_at(Timestamp::new("2026-05-19T00:00:00Z".into(), monotonic_ns).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
async fn sealer_commits_batch_to_localnet() {
    let test_name = "sealer_commits_batch_to_localnet";
    let Some(rpc_url) = env_or_skip(test_name, "YUTHA_SUI_RPC_URL") else {
        return;
    };
    let Some(package_id) = env_or_skip(test_name, "YUTHA_SUI_PACKAGE_ID") else {
        return;
    };
    let Some(swarm_anchor_id) = env_or_skip(test_name, "YUTHA_SUI_SWARM_ANCHOR_ID") else {
        return;
    };
    let Some(sealer_key_path) = env_or_skip(test_name, "YUTHA_SUI_SEALER_KEY") else {
        return;
    };

    let sealer_key = load_sealer_key_from_file(&sealer_key_path)
        .expect("load sealer key from YUTHA_SUI_SEALER_KEY");

    let client =
        RpcAnchorClient::connect(&rpc_url, sealer_key.clone(), &package_id, &swarm_anchor_id)
            .expect("connect Sui RPC client");

    // Verify we can read the anchor state up front.
    let before = client
        .read_anchor_state()
        .await
        .expect("read_anchor_state before");
    eprintln!(
        "[{test_name}] pre-commit anchor state: batch_count={}, last_ns_range_end={}",
        before.batch_count, before.last_ns_range_end
    );

    // Construct a sealer and seal a small batch. The swarm_id MUST
    // match what create_swarm_anchor was called with on-chain;
    // otherwise the canonical preimage diverges and on-chain
    // signature verify aborts with ESealerKeyMismatch.
    let swarm_id = SwarmId::from_bytes(&[0x42; 16]).unwrap();
    let sealer: Arc<dyn Sealer> = Arc::new(SuiSealer::new(
        Box::new(client.clone()),
        sealer_key,
        swarm_id,
    ));

    // Pick ns values strictly greater than the on-chain watermark
    // so the monotonic check passes.
    let base_ns = before.last_ns_range_end + 1000;
    let receipts = vec![fixture(base_ns, 1), fixture(base_ns + 100, 2)];

    let batch = sealer.seal_batch(&receipts).await.expect("seal_batch");
    eprintln!(
        "[{test_name}] sealed batch_root={} commit_tx={}",
        bytes_to_hex(&batch.batch_root.digest),
        bytes_to_hex(&batch.commitment_id)
    );

    assert_eq!(batch.commitment_id.len(), 32, "Sui tx digest is 32 bytes");
    assert_eq!(batch.leaves.len(), 2);

    // Confirm the on-chain state advanced.
    let after = client
        .read_anchor_state()
        .await
        .expect("read_anchor_state after");
    eprintln!(
        "[{test_name}] post-commit anchor state: batch_count={}, last_ns_range_end={}",
        after.batch_count, after.last_ns_range_end
    );
    assert_eq!(after.batch_count, before.batch_count + 1);
    assert_eq!(after.last_ns_range_end, batch.ns_range.1);
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
