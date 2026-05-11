// Package interop holds the differential-conformance test that proves the
// Yutha Receipt wire format is byte-identical between the Rust reference
// implementation and a stock protoc-gen-go / google.golang.org/protobuf
// implementation.
//
// Run with `make test` (or `go test ./...`). The test will fail with a
// clear "package not found" error if `make regen` hasn't been run; see
// README.md for setup.
package interop_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/yutha/yutha/interop/go/gen/yutha/common/v1"
	receiptv1 "github.com/yutha/yutha/interop/go/gen/yutha/receipt/v1"
)

// -----------------------------------------------------------------------------
// Fixture schema — mirrors crates/yutha-receipt/tests/vectors.rs
// -----------------------------------------------------------------------------

type receiptVector struct {
	Name                 string        `json:"name"`
	Description          string        `json:"description"`
	Kind                 string        `json:"kind"`
	Fields               receiptFields `json:"fields"`
	ExpectedCanonicalHex string        `json:"expected_canonical_hex"`
}

type receiptFields struct {
	SpecVersion         string           `json:"spec_version"`
	SwarmIDHex          string           `json:"swarm_id_hex"`
	ActorHex            string           `json:"actor_hex"`
	ActionKind          string           `json:"action_kind"`
	ConstitutionVersion string           `json:"constitution_version"`
	OccurredAt          timestampFields  `json:"occurred_at"`
	PredecessorsHex     []string         `json:"predecessors_hex"`
	Evidence            []evidenceFields `json:"evidence"`
	Cost                *costFields      `json:"cost"`
}

type timestampFields struct {
	WallClock   string `json:"wall_clock"`
	MonotonicNs uint64 `json:"monotonic_ns"`
}

type evidenceFields struct {
	Key       string `json:"key"`
	TypeURL   string `json:"type_url"`
	ValueHex  string `json:"value_hex"`
	Sensitive bool   `json:"sensitive"`
}

type costFields struct {
	InputTokens      uint64 `json:"input_tokens"`
	OutputTokens     uint64 `json:"output_tokens"`
	ToolCallCount    uint64 `json:"tool_call_count"`
	WallTimeMs       uint64 `json:"wall_time_ms"`
	UsdCentsEstimate string `json:"usd_cents_estimate"`
	ModelProvider    string `json:"model_provider"`
	ModelName        string `json:"model_name"`
	ModelVersion     string `json:"model_version"`
}

// -----------------------------------------------------------------------------
// Fixture → proto.Receipt
// -----------------------------------------------------------------------------

// mustHex panics on invalid hex. Acceptable inside a test driver because
// the fixtures are checked-in known-good values; a panic here means a typo
// in the fixture, which we want to surface loudly.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex %q: %v", s, err))
	}
	return b
}

func buildReceipt(f receiptFields) *receiptv1.Receipt {
	// IMPORTANT — match Rust's `to_canonical_proto()` shape:
	//   - Causal is always Some(...) even when predecessors is empty.
	//     prost emits the empty-message tag; we must too.
	//   - signatures / seal / extensions are NEVER set. They're absent in
	//     the canonical form by definition.
	causal := &commonv1.CausalRef{
		Predecessors: make([]*commonv1.Hash, 0, len(f.PredecessorsHex)),
	}
	for _, h := range f.PredecessorsHex {
		causal.Predecessors = append(causal.Predecessors, &commonv1.Hash{
			Algorithm: commonv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
			Digest:    mustHex(h),
		})
	}

	r := &receiptv1.Receipt{
		SpecVersion:         &commonv1.Version{Value: f.SpecVersion},
		SwarmId:             &commonv1.SwarmId{Value: mustHex(f.SwarmIDHex)},
		Actor:               &commonv1.AgentId{Value: mustHex(f.ActorHex)},
		ActionKind:          f.ActionKind,
		ConstitutionVersion: f.ConstitutionVersion,
		OccurredAt: &commonv1.Timestamp{
			WallClock:   f.OccurredAt.WallClock,
			MonotonicNs: f.OccurredAt.MonotonicNs,
		},
		Causal: causal,
	}

	for _, e := range f.Evidence {
		r.Evidence = append(r.Evidence, &receiptv1.Evidence{
			Key:       e.Key,
			TypeUrl:   e.TypeURL,
			Value:     mustHex(e.ValueHex),
			Sensitive: e.Sensitive,
		})
	}

	if f.Cost != nil {
		r.Cost = &commonv1.CostAnnotation{
			InputTokens:      f.Cost.InputTokens,
			OutputTokens:     f.Cost.OutputTokens,
			ToolCallCount:    f.Cost.ToolCallCount,
			WallTimeMs:       f.Cost.WallTimeMs,
			UsdCentsEstimate: f.Cost.UsdCentsEstimate,
			ModelProvider:    f.Cost.ModelProvider,
			ModelName:        f.Cost.ModelName,
			ModelVersion:     f.Cost.ModelVersion,
		}
	}

	return r
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

// vectorsBase returns the parent of every per-kind vectors directory.
// Tests run from /interop/go/; vectors live at /spec/vectors/<kind>/.
// Used by every TestXxxVectorsMatch in this package.
func vectorsBase(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..", "spec", "vectors")
}

func TestReceiptVectorsMatch(t *testing.T) {
	dir := filepath.Join(vectorsBase(t), "receipt")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read_dir %s: %v", dir, err)
	}

	var paths []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	// Stable iteration order — test output is easier to diff across runs.
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no receipt vectors found in %s", dir)
	}

	marshaler := proto.MarshalOptions{Deterministic: true}

	var failures []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: read: %v", path, err))
			continue
		}

		var v receiptVector
		if err := json.Unmarshal(raw, &v); err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse: %v", path, err))
			continue
		}
		if v.Kind != "receipt" {
			continue
		}

		msg := buildReceipt(v.Fields)
		bytes, err := marshaler.Marshal(msg)
		if err != nil {
			failures = append(failures, fmt.Sprintf("[%s] marshal: %v", v.Name, err))
			continue
		}
		actualHex := hex.EncodeToString(bytes)
		if actualHex != v.ExpectedCanonicalHex {
			failures = append(failures, fmt.Sprintf(
				"[%s] canonical bytes diverged from fixture\n  expected: %s\n  actual:   %s",
				v.Name, v.ExpectedCanonicalHex, actualHex,
			))
		}
	}

	if len(failures) > 0 {
		t.Fatalf("%d vector(s) failed:\n\n%s", len(failures), strings.Join(failures, "\n\n"))
	}
}
