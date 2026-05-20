// Canonical-preimage conformance vectors (Move side).
//
// Mirrors `crates/yutha-receipt/tests/preimage_vectors.rs` — both
// tests load the same fixture inputs from
// `/spec/vectors/sui-anchoring/preimage/` and assert byte-equality
// against the same `expected_preimage_hex`. If either encoder
// drifts from the spec, this test fires at `sui move test` time
// rather than at production commit time with a generic
// `ESealerKeyMismatch`.
//
// Move can't easily read JSON from disk, so the vector inputs +
// expected bytes are inlined here as byte-vector literals. Each
// test block carries a `// fixture: <filename>` comment so a
// reviewer can cross-check against the JSON source.

#[test_only]
module receipt_anchor::preimage_vectors_tests {
    use receipt_anchor::receipt_anchor::canonical_preimage_for_testing;
    // `std::vector` is auto-imported in Sui 1.x; explicit `use` would
    // just be a duplicate-alias warning.

    // ---------- helpers ----------

    /// Build a byte vector by repeating `byte` `count` times.
    fun bytes_repeated(byte: u8, count: u64): vector<u8> {
        let mut v: vector<u8> = vector[];
        let mut i: u64 = 0;
        while (i < count) {
            vector::push_back(&mut v, byte);
            i = i + 1;
        };
        v
    }

    /// Build a byte vector of length 32 with bytes 0x01..0x20 (matches
    /// the `multi_kind_lex_sort` fixture's batch_root).
    fun sequential_1_through_32(): vector<u8> {
        let mut v: vector<u8> = vector[];
        let mut i: u8 = 1;
        while (i <= 32) {
            vector::push_back(&mut v, i);
            i = i + 1;
        };
        v
    }

    // ---------- fixture: single_kind_minimal.json ----------

    #[test]
    fun vector_single_kind_minimal() {
        // inputs.swarm_id_hex = "42" * 16
        let swarm_id = bytes_repeated(0x42, 16);
        // inputs.batch_root_hex = "aa" * 32
        let batch_root = bytes_repeated(0xAA, 32);
        let count: u64 = 1;
        let ns_start: u64 = 100;
        let ns_end: u64 = 100;
        // inputs.histogram = [["envelope.send", 1]]
        let keys: vector<vector<u8>> = vector[b"envelope.send"];
        let values: vector<u64> = vector[1];

        let got = canonical_preimage_for_testing(
            swarm_id, batch_root, count, ns_start, ns_end, keys, values,
        );

        // expected_preimage_hex, parsed as bytes
        let expected: vector<u8> = vector[
            // swarm_id (16 bytes)
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            // batch_root (32 bytes)
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            // count = 1 (u64 BE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // ns_range_start = 100 = 0x64 (u64 BE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
            // ns_range_end = 100 (u64 BE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
            // entry_count = 1 (u32 BE)
            0x00, 0x00, 0x00, 0x01,
            // entry: key_len = 13 (0x0d)
            0x0D,
            // key: "envelope.send" (UTF-8 bytes)
            0x65, 0x6E, 0x76, 0x65, 0x6C, 0x6F, 0x70, 0x65,
            0x2E, 0x73, 0x65, 0x6E, 0x64,
            // count for this kind = 1 (u64 BE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        assert!(got == expected, 0);
    }

    // ---------- fixture: multi_kind_lex_sort.json ----------

    #[test]
    fun vector_multi_kind_lex_sort() {
        // inputs.swarm_id_hex = "00" * 16
        let swarm_id = bytes_repeated(0x00, 16);
        // inputs.batch_root_hex = 0x01..0x20
        let batch_root = sequential_1_through_32();
        let count: u64 = 11;
        let ns_start: u64 = 1000;
        let ns_end: u64 = 2000;
        // Histogram pre-sorted lex-ascending: agent.register < envelope.deliver < envelope.send
        let keys: vector<vector<u8>> = vector[
            b"agent.register",
            b"envelope.deliver",
            b"envelope.send",
        ];
        let values: vector<u64> = vector[1, 5, 5];

        let got = canonical_preimage_for_testing(
            swarm_id, batch_root, count, ns_start, ns_end, keys, values,
        );

        let expected: vector<u8> = vector[
            // swarm_id (16 zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // batch_root (0x01..0x20)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            // count = 11 = 0x0B (u64 BE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B,
            // ns_range_start = 1000 = 0x03E8 (u64 BE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8,
            // ns_range_end = 2000 = 0x07D0 (u64 BE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xD0,
            // entry_count = 3 (u32 BE)
            0x00, 0x00, 0x00, 0x03,
            // Entry 1: "agent.register" (len 14, 0x0E), count = 1
            0x0E,
            0x61, 0x67, 0x65, 0x6E, 0x74, 0x2E, 0x72, 0x65,
            0x67, 0x69, 0x73, 0x74, 0x65, 0x72,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Entry 2: "envelope.deliver" (len 16, 0x10), count = 5
            0x10,
            0x65, 0x6E, 0x76, 0x65, 0x6C, 0x6F, 0x70, 0x65,
            0x2E, 0x64, 0x65, 0x6C, 0x69, 0x76, 0x65, 0x72,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            // Entry 3: "envelope.send" (len 13, 0x0D), count = 5
            0x0D,
            0x65, 0x6E, 0x76, 0x65, 0x6C, 0x6F, 0x70, 0x65,
            0x2E, 0x73, 0x65, 0x6E, 0x64,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ];

        assert!(got == expected, 0);
    }
}
