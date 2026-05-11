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
	passportv1 "github.com/yutha/yutha/interop/go/gen/yutha/passport/v1"
)

// -----------------------------------------------------------------------------
// Fixture schema — mirrors crates/yutha-passport/tests/vectors.rs
// -----------------------------------------------------------------------------

type passportVector struct {
	Name                 string         `json:"name"`
	Description          string         `json:"description"`
	Kind                 string         `json:"kind"`
	Fields               passportFields `json:"fields"`
	ExpectedCanonicalHex string         `json:"expected_canonical_hex"`
}

type passportFields struct {
	SpecVersion                 string                          `json:"spec_version"`
	AgentIDHex                  string                          `json:"agent_id_hex"`
	SwarmIDHex                  string                          `json:"swarm_id_hex"`
	AgentPublicKey              publicKeyFields                 `json:"agent_public_key"`
	Owner                       string                          `json:"owner"`
	Framework                   string                          `json:"framework"`
	FrameworkVersion            string                          `json:"framework_version"`
	Capabilities                []capabilityDeclarationFields   `json:"capabilities"`
	AcceptedConstitutionVersion string                          `json:"accepted_constitution_version"`
	Tier                        string                          `json:"tier"`
	Resources                   resourceDeclarationFields       `json:"resources"`
	IssuedAt                    timestampFields                 `json:"issued_at"`
	ExpiresAt                   *timestampFields                `json:"expires_at"`
	DefaultModelProvider        string                          `json:"default_model_provider"`
	DefaultModelName            string                          `json:"default_model_name"`
}

type publicKeyFields struct {
	Algorithm string `json:"algorithm"`
	ValueHex  string `json:"value_hex"`
}

type capabilityDeclarationFields struct {
	Kind         string            `json:"kind"`
	ResourceTags []string          `json:"resource_tags"`
	Bounds       map[string]string `json:"bounds"`
	Description  string            `json:"description"`
}

type resourceDeclarationFields struct {
	MaxConcurrentActions  uint64 `json:"max_concurrent_actions"`
	MaxMessagesPerMinute  uint64 `json:"max_messages_per_minute"`
	MaxToolCallsPerHour   uint64 `json:"max_tool_calls_per_hour"`
	MaxUsdPerDayCents     string `json:"max_usd_per_day_cents"`
	MaxMemoryBytes        uint64 `json:"max_memory_bytes"`
}

// timestampFields and mustHexBytes live in vectors_test.go (same package).

// -----------------------------------------------------------------------------
// Parse helpers
// -----------------------------------------------------------------------------

func parseAlgorithm(s string) commonv1.SignatureAlgorithm {
	switch s {
	case "ed25519":
		return commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519
	case "reserved_pq":
		return commonv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_RESERVED_PQ
	default:
		panic(fmt.Sprintf("unknown signature algorithm: %q", s))
	}
}

func parsePassportTier(s string) passportv1.PassportTier {
	switch s {
	case "minimal":
		return passportv1.PassportTier_PASSPORT_TIER_MINIMAL
	case "standard":
		return passportv1.PassportTier_PASSPORT_TIER_STANDARD
	case "verifiable":
		return passportv1.PassportTier_PASSPORT_TIER_VERIFIABLE
	default:
		panic(fmt.Sprintf("unknown passport tier: %q", s))
	}
}

// -----------------------------------------------------------------------------
// Fixture → proto.Passport
// -----------------------------------------------------------------------------

func buildPassport(f passportFields) *passportv1.Passport {
	p := &passportv1.Passport{
		SpecVersion:                 &commonv1.Version{Value: f.SpecVersion},
		AgentId:                     &commonv1.AgentId{Value: mustHex(f.AgentIDHex)},
		SwarmId:                     &commonv1.SwarmId{Value: mustHex(f.SwarmIDHex)},
		AgentPublicKey:              &commonv1.PublicKey{
			Algorithm: parseAlgorithm(f.AgentPublicKey.Algorithm),
			Value:     mustHex(f.AgentPublicKey.ValueHex),
		},
		Owner:                       f.Owner,
		Framework:                   f.Framework,
		FrameworkVersion:            f.FrameworkVersion,
		AcceptedConstitutionVersion: f.AcceptedConstitutionVersion,
		Tier:                        parsePassportTier(f.Tier),
		Resources: &passportv1.ResourceDeclaration{
			MaxConcurrentActions:  f.Resources.MaxConcurrentActions,
			MaxMessagesPerMinute:  f.Resources.MaxMessagesPerMinute,
			MaxToolCallsPerHour:   f.Resources.MaxToolCallsPerHour,
			MaxUsdPerDayCents:     f.Resources.MaxUsdPerDayCents,
			MaxMemoryBytes:        f.Resources.MaxMemoryBytes,
		},
		IssuedAt: &commonv1.Timestamp{
			WallClock:   f.IssuedAt.WallClock,
			MonotonicNs: f.IssuedAt.MonotonicNs,
		},
		DefaultModelProvider: f.DefaultModelProvider,
		DefaultModelName:     f.DefaultModelName,
	}

	if f.ExpiresAt != nil {
		p.ExpiresAt = &commonv1.Timestamp{
			WallClock:   f.ExpiresAt.WallClock,
			MonotonicNs: f.ExpiresAt.MonotonicNs,
		}
	}

	for _, c := range f.Capabilities {
		// Go's encoding/json gives us a regular map[string]string for
		// Bounds. Iteration order is random — but the wire encoding
		// sorts keys lexicographically because we use
		// MarshalOptions{Deterministic: true}. Insertion order is
		// irrelevant.
		p.Capabilities = append(p.Capabilities, &passportv1.CapabilityDeclaration{
			Kind:         c.Kind,
			ResourceTags: append([]string(nil), c.ResourceTags...),
			Bounds:       c.Bounds,
			Description:  c.Description,
		})
	}

	return p
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

func TestPassportVectorsMatch(t *testing.T) {
	dir := filepath.Join(vectorsBase(t), "passport")
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
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no passport vectors found in %s", dir)
	}

	marshaler := proto.MarshalOptions{Deterministic: true}

	var failures []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: read: %v", path, err))
			continue
		}
		var v passportVector
		if err := json.Unmarshal(raw, &v); err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse: %v", path, err))
			continue
		}
		if v.Kind != "passport" {
			continue
		}
		msg := buildPassport(v.Fields)
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
		t.Fatalf("%d passport vector(s) failed:\n\n%s",
			len(failures), strings.Join(failures, "\n\n"))
	}
}
