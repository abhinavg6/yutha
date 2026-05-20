// Yutha receipt anchoring — Move package for verifiability Layer 1.
//
// Spec: /spec/verifiability/sui-anchoring.md §5 (Sui Move module).
// RFC:  /spec/rfcs/0014-sui-receipt-anchoring.md.
//
// Operators publish their own copy of this package per RFC 0014's
// operator-owned model. The package's purpose is single-call per
// batch: receive `commit_batch` from a sealer holding the right
// Ed25519 key, verify the signature on-chain, advance the per-swarm
// monotonic batch counter, and emit an `AnchorCommitted` event.

module receipt_anchor::receipt_anchor {
    // Sui 1.x auto-imports `std::vector`, `sui::object`, `sui::transfer`,
    // and `sui::tx_context::TxContext` in every module — explicit `use`
    // lines for those would just be duplicate-alias warnings. Only
    // bring in the ones that aren't auto-imported.
    use sui::clock::{Self, Clock};
    use sui::ed25519;
    use sui::event;
    use sui::vec_map::{Self, VecMap};

    // -----------------------------------------------------------------
    // Bounds — match /spec/verifiability/sui-anchoring.md §3-§4.
    // -----------------------------------------------------------------

    /// `batch_root` is a SHA-256 digest (32 bytes).
    const BATCH_ROOT_LEN: u64 = 32;
    /// Ed25519 signature is 64 bytes.
    const SIGNATURE_LEN: u64 = 64;
    /// Ed25519 public key is 32 bytes (raw, not PKCS#8).
    const PUBKEY_LEN: u64 = 32;
    /// `swarm_id` is a 16-byte UUID value.
    const SWARM_ID_LEN: u64 = 16;
    /// Max length of an action_kind histogram key. Self-enforced by the
    /// u8 wire-format length prefix; mirrored here for explicit aborts.
    const MAX_ACTION_KIND_LEN: u64 = 255;

    // -----------------------------------------------------------------
    // Abort codes — match /spec/verifiability/sui-anchoring.md §5.5.
    // -----------------------------------------------------------------

    const EBatchRootLength: u64 = 1;
    const ESignatureLength: u64 = 2;
    const EPubkeyLength: u64 = 3;
    const ESwarmIdLength: u64 = 4;
    const ENsRangeNotMonotonic: u64 = 5;
    const ENsRangeInvalid: u64 = 6;
    const EHistogramSumMismatch: u64 = 7;
    const EHistogramKeyTooLong: u64 = 8;
    const ESealerKeyMismatch: u64 = 9;
    /// Histogram entries arrived out of lex-ascending key order. The
    /// Rust sealer ALWAYS sends sorted entries (BTreeMap iterates in
    /// key order); this abort fires for buggy / malicious callers.
    /// Without this check, an out-of-order histogram would silently
    /// fail signature verification (canonical preimage wouldn't match
    /// the signed bytes) — confusing operators. The explicit code
    /// makes the failure mode clear.
    const EHistogramNotSorted: u64 = 10;
    /// Parallel-array histogram entry: keys.len() != values.len().
    /// Only surfaced by the PTB-friendly entry point
    /// `commit_batch_from_arrays`; the typed `commit_batch` API cannot
    /// reach this state because the `VecMap` keeps them paired.
    const EHistogramLengthMismatch: u64 = 11;

    // -----------------------------------------------------------------
    // Shared state
    // -----------------------------------------------------------------

    /// One shared object per Yutha swarm. Holds the rolling commitment
    /// history. Operators create this once via `create_swarm_anchor`
    /// and pass its object id to the control plane as
    /// `--anchor-swarm-anchor-id`.
    public struct SwarmAnchor has key {
        id: UID,
        /// 16-byte UUID identifying the Yutha swarm.
        swarm_id: vector<u8>,
        /// 32-byte raw Ed25519 public key of the sealer authorized to
        /// commit batches against this anchor. Anchors signed by
        /// any other key abort with ESealerKeyMismatch.
        sealer_pubkey: vector<u8>,
        /// Monotonically incremented on every successful commit.
        /// Serves as the public `batch_index` of the next batch.
        batch_count: u64,
        /// `ns_range_end` of the last successfully-committed batch.
        /// Used to enforce monotonic ns-range invariant
        /// (`ENsRangeNotMonotonic`). Initialized to 0; the very first
        /// batch's `ns_range_start >= 0` trivially holds.
        last_ns_range_end: u64,
        /// Wall-clock ms (from `sui::clock::Clock`) at create-time.
        /// Informational; not used in invariant checks.
        created_at_ms: u64,
    }

    /// Emitted on every successful `commit_batch`. The on-chain event
    /// stream is the foundation for any operator observability —
    /// Sui indexers (Suiscan, Suivision, self-hosted) consume these
    /// directly per RFC 0014 §3.
    public struct AnchorCommitted has copy, drop {
        swarm_id: vector<u8>,
        /// Value of `SwarmAnchor.batch_count` BEFORE this commit.
        batch_index: u64,
        /// 32-byte SHA-256 Merkle root of the batch's receipts.
        batch_root: vector<u8>,
        count: u64,
        ns_range_start: u64,
        ns_range_end: u64,
        action_kind_histogram: VecMap<vector<u8>, u64>,
        anchored_at_ms: u64,
    }

    // -----------------------------------------------------------------
    // Entry functions
    // -----------------------------------------------------------------

    /// Create a fresh `SwarmAnchor` and share it. Operators call this
    /// once per swarm (or once per package-deploy/migration).
    ///
    /// Length checks abort with `ESwarmIdLength` (16-byte swarm_id) or
    /// `EPubkeyLength` (32-byte sealer_pubkey) on malformed input.
    public fun create_swarm_anchor(
        swarm_id: vector<u8>,
        sealer_pubkey: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(vector::length(&swarm_id) == SWARM_ID_LEN, ESwarmIdLength);
        assert!(vector::length(&sealer_pubkey) == PUBKEY_LEN, EPubkeyLength);

        let anchor = SwarmAnchor {
            id: object::new(ctx),
            swarm_id,
            sealer_pubkey,
            batch_count: 0,
            last_ns_range_end: 0,
            created_at_ms: clock::timestamp_ms(clock),
        };
        transfer::share_object(anchor);
    }

    /// Commit a sealed batch on-chain. Aborts if any structural or
    /// signature check fails; on success, advances `batch_count` and
    /// `last_ns_range_end` and emits an `AnchorCommitted` event.
    ///
    /// Order of checks (matches /spec/verifiability/sui-anchoring.md
    /// §5.4 and §5.5):
    ///   1. Length: batch_root (32) + signature (64).
    ///   2. NsRange validity: ns_range_start <= ns_range_end.
    ///   3. Monotonic: ns_range_start >= anchor.last_ns_range_end.
    ///   4. Histogram sum: sum of values == count.
    ///   5. Histogram keys: each <= 255 bytes; entries lex-sorted.
    ///   6. Ed25519 signature over the canonical preimage matches
    ///      the registered sealer_pubkey.
    public fun commit_batch(
        anchor: &mut SwarmAnchor,
        batch_root: vector<u8>,
        count: u64,
        ns_range_start: u64,
        ns_range_end: u64,
        action_kind_histogram: VecMap<vector<u8>, u64>,
        sealer_signature: vector<u8>,
        clock: &Clock,
        _ctx: &mut TxContext,
    ) {
        // 1. Length checks.
        assert!(vector::length(&batch_root) == BATCH_ROOT_LEN, EBatchRootLength);
        assert!(vector::length(&sealer_signature) == SIGNATURE_LEN, ESignatureLength);

        // 2. ns-range validity.
        assert!(ns_range_start <= ns_range_end, ENsRangeInvalid);

        // 3. Monotonic check against the anchor's high-water mark.
        // The very first batch (anchor.last_ns_range_end == 0) trivially
        // satisfies this for any ns_range_start >= 0.
        assert!(ns_range_start >= anchor.last_ns_range_end, ENsRangeNotMonotonic);

        // 4 + 5. Histogram structural validation (sum + per-key length +
        // lex-ascending order). Combined into one pass so we iterate
        // the VecMap only once.
        validate_histogram(&action_kind_histogram, count);

        // 6. Reconstruct canonical preimage + verify signature. The
        // preimage layout must match the Rust sealer's
        // `canonical_preimage` byte-for-byte; see
        // /spec/verifiability/sui-anchoring.md §4 for the spec and
        // crates/yutha-receipt/src/preimage.rs for the off-chain impl.
        let preimage = build_canonical_preimage(
            &anchor.swarm_id,
            &batch_root,
            count,
            ns_range_start,
            ns_range_end,
            &action_kind_histogram,
        );

        assert!(
            ed25519::ed25519_verify(&sealer_signature, &anchor.sealer_pubkey, &preimage),
            ESealerKeyMismatch,
        );

        // Advance anchor state. batch_index in the emitted event is the
        // batch's index — the value of `batch_count` BEFORE this
        // increment.
        let batch_index = anchor.batch_count;
        anchor.batch_count = batch_index + 1;
        anchor.last_ns_range_end = ns_range_end;

        // Emit the public event. swarm_id is copied by value (vector<u8>
        // copies are cheap at the typical 16-byte size); action_kind_histogram
        // moves into the event (we don't need it after this point).
        event::emit(AnchorCommitted {
            swarm_id: anchor.swarm_id,
            batch_index,
            batch_root,
            count,
            ns_range_start,
            ns_range_end,
            action_kind_histogram,
            anchored_at_ms: clock::timestamp_ms(clock),
        });
    }

    /// PTB-friendly wrapper around [`commit_batch`].
    ///
    /// Sui PTBs forbid passing arbitrary Move structs (including
    /// `VecMap<K, V>`) as "pure" arguments — only primitives,
    /// `vector<u8>`, `string`, and nested vectors of those are allowed.
    /// The off-chain Rust sealer therefore can't build a `VecMap`
    /// directly; instead it sends the histogram as two parallel
    /// pure-friendly vectors (`histogram_keys: vector<vector<u8>>` +
    /// `histogram_values: vector<u64>`), and this wrapper assembles
    /// the `VecMap` on-chain before delegating to `commit_batch` for
    /// the actual validation / signature-verify / state advance.
    ///
    /// Indexes are zipped in order — `histogram_keys[i]` pairs with
    /// `histogram_values[i]`. The Rust sealer's `BTreeMap` iteration
    /// order is lex-ascending on keys, which is what
    /// `commit_batch`'s `EHistogramNotSorted` check requires.
    public fun commit_batch_from_arrays(
        anchor: &mut SwarmAnchor,
        batch_root: vector<u8>,
        count: u64,
        ns_range_start: u64,
        ns_range_end: u64,
        histogram_keys: vector<vector<u8>>,
        histogram_values: vector<u64>,
        sealer_signature: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let n = vector::length(&histogram_keys);
        assert!(
            n == vector::length(&histogram_values),
            EHistogramLengthMismatch,
        );

        // Build the VecMap in input-order (i.e. lex-ascending, since the
        // Rust sealer's BTreeMap iterates that way). `vec_map::insert`
        // appends; the `EHistogramNotSorted` check in `commit_batch`
        // traverses by index and will fire if the caller passed
        // out-of-order keys.
        //
        // Read-by-index copies the elements out — `vector<u8>` and
        // `u64` both have `copy`, so the deref-from-borrow is cheap.
        // The input vectors are dropped at function exit automatically.
        let mut histogram = vec_map::empty<vector<u8>, u64>();
        let mut i: u64 = 0;
        while (i < n) {
            let k = *vector::borrow(&histogram_keys, i);
            let v = *vector::borrow(&histogram_values, i);
            vec_map::insert(&mut histogram, k, v);
            i = i + 1;
        };

        commit_batch(
            anchor,
            batch_root,
            count,
            ns_range_start,
            ns_range_end,
            histogram,
            sealer_signature,
            clock,
            ctx,
        );
    }

    // -----------------------------------------------------------------
    // Read accessors — useful for off-chain indexers / sealers that
    // want to peek at anchor state without taking a write lock.
    // -----------------------------------------------------------------

    public fun batch_count(anchor: &SwarmAnchor): u64 {
        anchor.batch_count
    }

    public fun last_ns_range_end(anchor: &SwarmAnchor): u64 {
        anchor.last_ns_range_end
    }

    public fun sealer_pubkey(anchor: &SwarmAnchor): &vector<u8> {
        &anchor.sealer_pubkey
    }

    public fun swarm_id(anchor: &SwarmAnchor): &vector<u8> {
        &anchor.swarm_id
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Single-pass histogram validation: lex-ascending keys, each key
    /// length <= MAX_ACTION_KIND_LEN, sum of values == count.
    fun validate_histogram(histogram: &VecMap<vector<u8>, u64>, count: u64) {
        let n = vec_map::length(histogram);
        let mut sum: u64 = 0;
        let mut i: u64 = 0;
        // `prev` is None at i=0; we track via a separate flag because
        // Move doesn't have Option<&vector<u8>> ergonomics here.
        let mut have_prev = false;
        let mut prev_idx: u64 = 0;

        while (i < n) {
            let (key, value) = vec_map::get_entry_by_idx(histogram, i);
            let key_len = vector::length(key);
            assert!(key_len <= MAX_ACTION_KIND_LEN, EHistogramKeyTooLong);

            if (have_prev) {
                let (prev_key, _) = vec_map::get_entry_by_idx(histogram, prev_idx);
                assert!(vector_lt(prev_key, key), EHistogramNotSorted);
            };

            sum = sum + *value;
            prev_idx = i;
            have_prev = true;
            i = i + 1;
        };

        assert!(sum == count, EHistogramSumMismatch);
    }

    /// Reconstruct the canonical preimage byte-for-byte. Layout per
    /// /spec/verifiability/sui-anchoring.md §4:
    ///
    ///   swarm_id (16)
    ///   batch_root (32)
    ///   count (u64 BE, 8)
    ///   ns_range_start (u64 BE, 8)
    ///   ns_range_end (u64 BE, 8)
    ///   entry_count (u32 BE, 4)
    ///   for each entry (lex-sorted):
    ///     key_len (u8, 1)
    ///     key (UTF-8 bytes)
    ///     value (u64 BE, 8)
    ///
    /// MUST stay in lockstep with `canonical_preimage` in
    /// `crates/yutha-receipt/src/preimage.rs`. Conformance vectors
    /// under `/spec/vectors/sui-anchoring/preimage/` (added in H7)
    /// pin specific input → output triples.
    fun build_canonical_preimage(
        swarm_id: &vector<u8>,
        batch_root: &vector<u8>,
        count: u64,
        ns_range_start: u64,
        ns_range_end: u64,
        histogram: &VecMap<vector<u8>, u64>,
    ): vector<u8> {
        let mut buf: vector<u8> = vector[];

        // Fixed header: 16 + 32 + 8 + 8 + 8 = 72 bytes.
        vector::append(&mut buf, *swarm_id);
        vector::append(&mut buf, *batch_root);
        append_u64_be(&mut buf, count);
        append_u64_be(&mut buf, ns_range_start);
        append_u64_be(&mut buf, ns_range_end);

        // Histogram. entry_count is encoded as u32 BE; well-formed batches
        // never approach u32::MAX entries (canonical action_kinds are ≈
        // 30-50 kinds), so this is generous headroom + matches the Rust
        // encoder.
        let n = vec_map::length(histogram);
        // Truncation cast: n is a u64 bounded by the VecMap, which in
        // practice fits comfortably in u32. Defensive check is in
        // `validate_histogram`'s sort-order traversal — if an attacker
        // somehow constructed a VecMap with > u32::MAX entries, the
        // resulting preimage would wrap and signature verify would
        // fail; the abort code would just be ESealerKeyMismatch rather
        // than something more specific.
        append_u32_be(&mut buf, (n as u32));

        let mut i: u64 = 0;
        while (i < n) {
            let (key, value) = vec_map::get_entry_by_idx(histogram, i);
            let key_len = (vector::length(key) as u8);
            vector::push_back(&mut buf, key_len);
            vector::append(&mut buf, *key);
            append_u64_be(&mut buf, *value);
            i = i + 1;
        };

        buf
    }

    /// Append a u64 in big-endian byte order to `buf`.
    fun append_u64_be(buf: &mut vector<u8>, value: u64) {
        vector::push_back(buf, (((value >> 56) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 48) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 40) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 32) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 24) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 16) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 8) & 0xFF) as u8));
        vector::push_back(buf, ((value & 0xFF) as u8));
    }

    /// Append a u32 in big-endian byte order to `buf`.
    fun append_u32_be(buf: &mut vector<u8>, value: u32) {
        vector::push_back(buf, (((value >> 24) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 16) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 8) & 0xFF) as u8));
        vector::push_back(buf, ((value & 0xFF) as u8));
    }

    /// Lexicographic byte-order less-than over two `vector<u8>` values.
    /// Used for the sort-order check; Move's standard library doesn't
    /// ship an `Ord` impl on byte vectors, so we roll our own.
    fun vector_lt(a: &vector<u8>, b: &vector<u8>): bool {
        let a_len = vector::length(a);
        let b_len = vector::length(b);
        let min_len = if (a_len < b_len) a_len else b_len;
        let mut i: u64 = 0;
        while (i < min_len) {
            let av = *vector::borrow(a, i);
            let bv = *vector::borrow(b, i);
            if (av < bv) return true;
            if (av > bv) return false;
            i = i + 1;
        };
        // Prefix-equal: shorter < longer.
        a_len < b_len
    }

    // -----------------------------------------------------------------
    // Test helpers — only compiled in `sui move test`. Lets tests
    // construct anchors with arbitrary state without going through
    // commit_batch (which requires a real signature).
    // -----------------------------------------------------------------

    #[test_only]
    public fun new_anchor_for_testing(
        swarm_id: vector<u8>,
        sealer_pubkey: vector<u8>,
        initial_batch_count: u64,
        initial_ns_range_end: u64,
        ctx: &mut TxContext,
    ): SwarmAnchor {
        SwarmAnchor {
            id: object::new(ctx),
            swarm_id,
            sealer_pubkey,
            batch_count: initial_batch_count,
            last_ns_range_end: initial_ns_range_end,
            created_at_ms: 0,
        }
    }

    #[test_only]
    public fun destroy_anchor_for_testing(anchor: SwarmAnchor) {
        let SwarmAnchor {
            id,
            swarm_id: _,
            sealer_pubkey: _,
            batch_count: _,
            last_ns_range_end: _,
            created_at_ms: _,
        } = anchor;
        object::delete(id);
    }

    #[test_only]
    public fun abort_code_batch_root_length(): u64 { EBatchRootLength }
    #[test_only]
    public fun abort_code_signature_length(): u64 { ESignatureLength }
    #[test_only]
    public fun abort_code_pubkey_length(): u64 { EPubkeyLength }
    #[test_only]
    public fun abort_code_swarm_id_length(): u64 { ESwarmIdLength }
    #[test_only]
    public fun abort_code_ns_range_not_monotonic(): u64 { ENsRangeNotMonotonic }
    #[test_only]
    public fun abort_code_ns_range_invalid(): u64 { ENsRangeInvalid }
    #[test_only]
    public fun abort_code_histogram_sum_mismatch(): u64 { EHistogramSumMismatch }
    #[test_only]
    public fun abort_code_histogram_key_too_long(): u64 { EHistogramKeyTooLong }
    #[test_only]
    public fun abort_code_sealer_key_mismatch(): u64 { ESealerKeyMismatch }
    #[test_only]
    public fun abort_code_histogram_not_sorted(): u64 { EHistogramNotSorted }

    /// Test-only entry point that exposes the (private) canonical-preimage
    /// encoder so cross-language conformance vectors can assert
    /// byte-equality against the Rust encoder.
    ///
    /// Inputs are passed as the same parallel-vectors shape
    /// `commit_batch_from_arrays` takes — the wrapper rebuilds the
    /// `VecMap` internally and delegates to
    /// [`build_canonical_preimage`]. Caller is responsible for passing
    /// keys in lex-ascending order (matches the Rust side; the
    /// `commit_batch` validation rejects non-sorted input at runtime,
    /// but this test helper trusts its caller).
    ///
    /// Sister test: `crates/yutha-receipt/tests/preimage_vectors.rs`.
    /// Vector fixtures: `/spec/vectors/sui-anchoring/preimage/`.
    #[test_only]
    public fun canonical_preimage_for_testing(
        swarm_id: vector<u8>,
        batch_root: vector<u8>,
        count: u64,
        ns_range_start: u64,
        ns_range_end: u64,
        histogram_keys: vector<vector<u8>>,
        histogram_values: vector<u64>,
    ): vector<u8> {
        let n = vector::length(&histogram_keys);
        assert!(n == vector::length(&histogram_values), EHistogramLengthMismatch);
        let mut histogram = vec_map::empty<vector<u8>, u64>();
        let mut i: u64 = 0;
        while (i < n) {
            let k = *vector::borrow(&histogram_keys, i);
            let v = *vector::borrow(&histogram_values, i);
            vec_map::insert(&mut histogram, k, v);
            i = i + 1;
        };
        build_canonical_preimage(
            &swarm_id,
            &batch_root,
            count,
            ns_range_start,
            ns_range_end,
            &histogram,
        )
    }
}
