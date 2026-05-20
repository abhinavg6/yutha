// Unit tests for the receipt_anchor Move module.
//
// Tests run via `sui move test` from /contracts/sui/receipt_anchor/.
// They exercise every abort code defined in receipt_anchor.move's
// §"Abort codes" block, plus the happy-path state-transition shape
// (covered by the integration test in H5/H6 against a real Sui
// localnet — Move unit tests can't mint Ed25519 signatures, only
// verify them, so the happy-path signature test is gated on having
// a Rust signer in the loop).

#[test_only]
module receipt_anchor::receipt_anchor_tests {
    use receipt_anchor::receipt_anchor::{
        Self, SwarmAnchor, new_anchor_for_testing, destroy_anchor_for_testing,
        abort_code_batch_root_length, abort_code_signature_length,
        abort_code_pubkey_length, abort_code_swarm_id_length,
        abort_code_ns_range_not_monotonic, abort_code_ns_range_invalid,
        abort_code_histogram_sum_mismatch, abort_code_histogram_key_too_long,
        abort_code_sealer_key_mismatch, abort_code_histogram_not_sorted,
    };
    // `std::vector` is auto-imported in Sui 1.x; explicit `use` for it
    // would just be a duplicate-alias warning.
    use sui::clock;
    use sui::test_scenario;
    use sui::vec_map;

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    const TEST_ADDR: address = @0xCAFE;

    fun valid_swarm_id(): vector<u8> {
        // 16 bytes — a deterministic UUID-shaped fixture. Real swarm ids
        // are UUID v7s; this is a fixed-byte stand-in.
        vector[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
    }

    fun valid_pubkey(): vector<u8> {
        // 32 bytes — a deterministic Ed25519 public-key-shaped fixture.
        // Not a real public key; tests that need the verify path to
        // actually succeed land in H5 with a Rust-minted real keypair.
        let mut v: vector<u8> = vector[];
        let mut i: u64 = 0;
        while (i < 32) {
            vector::push_back(&mut v, ((i + 1) as u8));
            i = i + 1;
        };
        v
    }

    fun valid_batch_root(): vector<u8> {
        let mut v: vector<u8> = vector[];
        let mut i: u64 = 0;
        while (i < 32) {
            vector::push_back(&mut v, ((i * 7 + 1) as u8));
            i = i + 1;
        };
        v
    }

    fun valid_signature(): vector<u8> {
        // 64 bytes — passes length validation but won't actually
        // verify against any real key. Tests for signature-mismatch
        // expect this to abort with ESealerKeyMismatch.
        let mut v: vector<u8> = vector[];
        let mut i: u64 = 0;
        while (i < 64) {
            vector::push_back(&mut v, ((i + 100) as u8));
            i = i + 1;
        };
        v
    }

    /// Minimal valid histogram: one entry, value = count.
    fun simple_histogram(count: u64): vec_map::VecMap<vector<u8>, u64> {
        let mut h = vec_map::empty<vector<u8>, u64>();
        vec_map::insert(&mut h, b"envelope.send", count);
        h
    }

    // -----------------------------------------------------------------
    // create_swarm_anchor
    // -----------------------------------------------------------------

    #[test]
    fun creates_and_shares_anchor() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        receipt_anchor::create_swarm_anchor(
            valid_swarm_id(),
            valid_pubkey(),
            &clk,
            ctx,
        );

        // Advance to the next tx to make the shared object retrievable.
        test_scenario::next_tx(&mut scenario, TEST_ADDR);
        let anchor = test_scenario::take_shared<SwarmAnchor>(&scenario);
        assert!(receipt_anchor::batch_count(&anchor) == 0, 0);
        assert!(receipt_anchor::last_ns_range_end(&anchor) == 0, 1);
        assert!(*receipt_anchor::sealer_pubkey(&anchor) == valid_pubkey(), 2);
        assert!(*receipt_anchor::swarm_id(&anchor) == valid_swarm_id(), 3);
        test_scenario::return_shared(anchor);

        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 4, location = receipt_anchor)] // ESwarmIdLength
    fun create_rejects_wrong_swarm_id_length() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        receipt_anchor::create_swarm_anchor(
            vector[0x01, 0x02, 0x03], // wrong length (3 bytes)
            valid_pubkey(),
            &clk,
            ctx,
        );

        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 3, location = receipt_anchor)] // EPubkeyLength
    fun create_rejects_wrong_pubkey_length() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        receipt_anchor::create_swarm_anchor(
            valid_swarm_id(),
            vector[0xAB, 0xCD], // wrong length (2 bytes)
            &clk,
            ctx,
        );

        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    // -----------------------------------------------------------------
    // commit_batch — length checks
    // -----------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = 1, location = receipt_anchor)] // EBatchRootLength
    fun commit_rejects_short_batch_root() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        let mut anchor = new_anchor_for_testing(
            valid_swarm_id(), valid_pubkey(), 0, 0, ctx,
        );

        receipt_anchor::commit_batch(
            &mut anchor,
            vector[0u8, 1u8, 2u8], // too short
            1,
            100,
            100,
            simple_histogram(1),
            valid_signature(),
            &clk,
            ctx,
        );

        destroy_anchor_for_testing(anchor);
        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 2, location = receipt_anchor)] // ESignatureLength
    fun commit_rejects_short_signature() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        let mut anchor = new_anchor_for_testing(
            valid_swarm_id(), valid_pubkey(), 0, 0, ctx,
        );

        receipt_anchor::commit_batch(
            &mut anchor,
            valid_batch_root(),
            1,
            100,
            100,
            simple_histogram(1),
            vector[0u8, 1u8], // too short
            &clk,
            ctx,
        );

        destroy_anchor_for_testing(anchor);
        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    // -----------------------------------------------------------------
    // commit_batch — ns-range invariants
    // -----------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = 6, location = receipt_anchor)] // ENsRangeInvalid
    fun commit_rejects_inverted_ns_range() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        let mut anchor = new_anchor_for_testing(
            valid_swarm_id(), valid_pubkey(), 0, 0, ctx,
        );

        receipt_anchor::commit_batch(
            &mut anchor,
            valid_batch_root(),
            1,
            200,   // ns_range_start
            100,   // ns_range_end (< start)
            simple_histogram(1),
            valid_signature(),
            &clk,
            ctx,
        );

        destroy_anchor_for_testing(anchor);
        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 5, location = receipt_anchor)] // ENsRangeNotMonotonic
    fun commit_rejects_non_monotonic_batches() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        // Set up an anchor that's already seen a batch ending at ns=1000.
        let mut anchor = new_anchor_for_testing(
            valid_swarm_id(), valid_pubkey(), 1, 1000, ctx,
        );

        // Try to commit a batch starting BEFORE the high-water mark.
        receipt_anchor::commit_batch(
            &mut anchor,
            valid_batch_root(),
            1,
            500,   // < anchor.last_ns_range_end (1000)
            600,
            simple_histogram(1),
            valid_signature(),
            &clk,
            ctx,
        );

        destroy_anchor_for_testing(anchor);
        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    // -----------------------------------------------------------------
    // commit_batch — histogram structural checks
    // -----------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = 7, location = receipt_anchor)] // EHistogramSumMismatch
    fun commit_rejects_histogram_sum_mismatch() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        let mut anchor = new_anchor_for_testing(
            valid_swarm_id(), valid_pubkey(), 0, 0, ctx,
        );

        // count=10 but histogram values sum to 1 (single entry of 1).
        receipt_anchor::commit_batch(
            &mut anchor,
            valid_batch_root(),
            10,
            100,
            100,
            simple_histogram(1),
            valid_signature(),
            &clk,
            ctx,
        );

        destroy_anchor_for_testing(anchor);
        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 8, location = receipt_anchor)] // EHistogramKeyTooLong
    fun commit_rejects_overlong_histogram_key() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        let mut anchor = new_anchor_for_testing(
            valid_swarm_id(), valid_pubkey(), 0, 0, ctx,
        );

        // 256-byte key exceeds the 255-byte limit.
        let mut long_key: vector<u8> = vector[];
        let mut i: u64 = 0;
        while (i < 256) {
            vector::push_back(&mut long_key, b"a"[0]);
            i = i + 1;
        };
        let mut hist = vec_map::empty<vector<u8>, u64>();
        vec_map::insert(&mut hist, long_key, 1);

        receipt_anchor::commit_batch(
            &mut anchor,
            valid_batch_root(),
            1,
            100,
            100,
            hist,
            valid_signature(),
            &clk,
            ctx,
        );

        destroy_anchor_for_testing(anchor);
        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 10, location = receipt_anchor)] // EHistogramNotSorted
    fun commit_rejects_unsorted_histogram() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        let mut anchor = new_anchor_for_testing(
            valid_swarm_id(), valid_pubkey(), 0, 0, ctx,
        );

        // Insert entries in non-lex-ascending order; sort-check fires.
        let mut hist = vec_map::empty<vector<u8>, u64>();
        vec_map::insert(&mut hist, b"zzz", 1);
        vec_map::insert(&mut hist, b"aaa", 1); // out of order

        receipt_anchor::commit_batch(
            &mut anchor,
            valid_batch_root(),
            2,
            100,
            100,
            hist,
            valid_signature(),
            &clk,
            ctx,
        );

        destroy_anchor_for_testing(anchor);
        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    // -----------------------------------------------------------------
    // commit_batch — signature verification (deny path)
    // -----------------------------------------------------------------

    #[test]
    #[expected_failure(abort_code = 9, location = receipt_anchor)] // ESealerKeyMismatch
    fun commit_rejects_bad_signature() {
        let mut scenario = test_scenario::begin(TEST_ADDR);
        let ctx = test_scenario::ctx(&mut scenario);
        let clk = clock::create_for_testing(ctx);

        let mut anchor = new_anchor_for_testing(
            valid_swarm_id(), valid_pubkey(), 0, 0, ctx,
        );

        // A 64-byte signature that won't verify against our pubkey.
        receipt_anchor::commit_batch(
            &mut anchor,
            valid_batch_root(),
            1,
            100,
            100,
            simple_histogram(1),
            valid_signature(),
            &clk,
            ctx,
        );

        destroy_anchor_for_testing(anchor);
        clock::destroy_for_testing(clk);
        test_scenario::end(scenario);
    }

    // -----------------------------------------------------------------
    // Abort-code accessor sanity — they exist + match the documented
    // values from /spec/verifiability/sui-anchoring.md §5.5.
    // -----------------------------------------------------------------

    #[test]
    fun abort_codes_match_spec() {
        assert!(abort_code_batch_root_length() == 1, 0);
        assert!(abort_code_signature_length() == 2, 0);
        assert!(abort_code_pubkey_length() == 3, 0);
        assert!(abort_code_swarm_id_length() == 4, 0);
        assert!(abort_code_ns_range_not_monotonic() == 5, 0);
        assert!(abort_code_ns_range_invalid() == 6, 0);
        assert!(abort_code_histogram_sum_mismatch() == 7, 0);
        assert!(abort_code_histogram_key_too_long() == 8, 0);
        assert!(abort_code_sealer_key_mismatch() == 9, 0);
        assert!(abort_code_histogram_not_sorted() == 10, 0);
    }

    // Happy-path note:
    //
    // A test that actually exercises the success branch of commit_batch
    // requires a real Ed25519 signature minted by the Rust sealer over
    // the canonical preimage. That cross-side integration test lives in
    // H5 (the yutha-anchor-sui crate) — there, the Rust SuiSealer
    // generates a signature, submits a real PTB against a Sui localnet,
    // and asserts the AnchorCommitted event fires + the anchor's
    // batch_count + last_ns_range_end advance.
    //
    // Why not here: Move's stdlib has ed25519_verify but no
    // ed25519_sign. We could hardcode a pre-minted (pubkey, preimage,
    // signature) triple, but that adds a maintenance burden — any
    // tweak to the canonical preimage layout would silently invalidate
    // the hardcoded vector unless someone regenerates it. The cleaner
    // path: leave the happy-path test for H5 where regeneration is
    // automatic from the Rust impl.
}
