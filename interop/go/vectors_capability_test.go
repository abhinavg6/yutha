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

	capv1 "github.com/yutha/yutha/interop/go/gen/yutha/capability/v1"
	commonv1 "github.com/yutha/yutha/interop/go/gen/yutha/common/v1"
)

// -----------------------------------------------------------------------------
// Fixture schema — mirrors crates/yutha-capability/tests/vectors.rs
// -----------------------------------------------------------------------------

type capabilityVector struct {
	Name                 string           `json:"name"`
	Description          string           `json:"description"`
	Kind                 string           `json:"kind"`
	Fields               capabilityFields `json:"fields"`
	ExpectedCanonicalHex string           `json:"expected_canonical_hex"`
}

type capabilityFields struct {
	SpecVersion         string            `json:"spec_version"`
	CapabilityIDHex     string            `json:"capability_id_hex"`
	SwarmIDHex          string            `json:"swarm_id_hex"`
	Issuer              json.RawMessage   `json:"issuer"`
	SubjectHex          string            `json:"subject_hex"`
	Scope               scopeFields       `json:"scope"`
	ParentHex           *string           `json:"parent_hex"`
	ValidFrom           timestampFields   `json:"valid_from"`
	ValidUntil          timestampFields   `json:"valid_until"`
	Caveats             []json.RawMessage `json:"caveats"`
	RevocationEndpoint  string            `json:"revocation_endpoint"`
}

type scopeFields struct {
	PermittedActions    []string          `json:"permitted_actions"`
	ResourceTags        []string          `json:"resource_tags"`
	Bounds              map[string]string `json:"bounds"`
	PermittedRecipients []string          `json:"permitted_recipients"`
	MemoryScopes        []string          `json:"memory_scopes"`
}

// Issuer / Caveat are tagged unions in the JSON. Discriminate on "kind".

type kindDiscriminator struct {
	Kind string `json:"kind"`
}

type issuerAgent struct {
	Kind     string `json:"kind"`
	AgentHex string `json:"agent_hex"`
}

type issuerOperator struct {
	Kind              string `json:"kind"`
	KeyFingerprintHex string `json:"key_fingerprint_hex"`
}

type issuerControlPlane struct {
	Kind                          string `json:"kind"`
	ControlPlaneKeyFingerprintHex string `json:"control_plane_key_fingerprint_hex"`
	InstanceID                    string `json:"instance_id"`
}

type caveatTimeOfDay struct {
	Kind    string `json:"kind"`
	FromUtc string `json:"from_utc"`
	ToUtc   string `json:"to_utc"`
}

type caveatConstitutionVersion struct {
	Kind       string  `json:"kind"`
	MinVersion string  `json:"min_version"`
	MaxVersion *string `json:"max_version"`
}

type caveatSupervisorRequired struct {
	Kind            string `json:"kind"`
	SupervisorRole  string `json:"supervisor_role"`
}

type caveatRateLimit struct {
	Kind          string `json:"kind"`
	MaxActions    uint32 `json:"max_actions"`
	WindowSeconds uint64 `json:"window_seconds"`
}

type caveatOnlyIfTagged struct {
	Kind         string   `json:"kind"`
	RequiredTags []string `json:"required_tags"`
}

type caveatNeverIfTagged struct {
	Kind          string   `json:"kind"`
	ForbiddenTags []string `json:"forbidden_tags"`
}

// -----------------------------------------------------------------------------
// Parse helpers
// -----------------------------------------------------------------------------

func parseIssuer(name string, raw json.RawMessage) *capv1.Issuer {
	var disc kindDiscriminator
	if err := json.Unmarshal(raw, &disc); err != nil {
		panic(fmt.Sprintf("[%s] issuer discriminator: %v", name, err))
	}
	out := &capv1.Issuer{}
	switch disc.Kind {
	case "agent":
		var a issuerAgent
		if err := json.Unmarshal(raw, &a); err != nil {
			panic(fmt.Sprintf("[%s] issuer.agent: %v", name, err))
		}
		out.Kind = &capv1.Issuer_Agent{
			Agent: &commonv1.AgentId{Value: mustHex(a.AgentHex)},
		}
	case "operator":
		var op issuerOperator
		if err := json.Unmarshal(raw, &op); err != nil {
			panic(fmt.Sprintf("[%s] issuer.operator: %v", name, err))
		}
		out.Kind = &capv1.Issuer_OperatorKeyFingerprint{
			OperatorKeyFingerprint: mustHex(op.KeyFingerprintHex),
		}
	case "control_plane":
		var cp issuerControlPlane
		if err := json.Unmarshal(raw, &cp); err != nil {
			panic(fmt.Sprintf("[%s] issuer.control_plane: %v", name, err))
		}
		out.Kind = &capv1.Issuer_ControlPlane{
			ControlPlane: &capv1.ControlPlaneIssuer{
				ControlPlaneKeyFingerprint: mustHex(cp.ControlPlaneKeyFingerprintHex),
				InstanceId:                 cp.InstanceID,
			},
		}
	default:
		panic(fmt.Sprintf("[%s] unknown issuer kind: %q", name, disc.Kind))
	}
	return out
}

func parseCaveat(name string, raw json.RawMessage) *capv1.Caveat {
	var disc kindDiscriminator
	if err := json.Unmarshal(raw, &disc); err != nil {
		panic(fmt.Sprintf("[%s] caveat discriminator: %v", name, err))
	}
	out := &capv1.Caveat{}
	switch disc.Kind {
	case "time_of_day":
		var c caveatTimeOfDay
		if err := json.Unmarshal(raw, &c); err != nil {
			panic(fmt.Sprintf("[%s] caveat.time_of_day: %v", name, err))
		}
		out.Kind = &capv1.Caveat_TimeOfDay{
			TimeOfDay: &capv1.TimeOfDayCaveat{FromUtc: c.FromUtc, ToUtc: c.ToUtc},
		}
	case "constitution_version":
		var c caveatConstitutionVersion
		if err := json.Unmarshal(raw, &c); err != nil {
			panic(fmt.Sprintf("[%s] caveat.constitution_version: %v", name, err))
		}
		maxV := ""
		if c.MaxVersion != nil {
			maxV = *c.MaxVersion
		}
		out.Kind = &capv1.Caveat_ConstitutionVersion{
			ConstitutionVersion: &capv1.ConstitutionVersionCaveat{
				MinVersion: c.MinVersion,
				MaxVersion: maxV,
			},
		}
	case "supervisor_required":
		var c caveatSupervisorRequired
		if err := json.Unmarshal(raw, &c); err != nil {
			panic(fmt.Sprintf("[%s] caveat.supervisor_required: %v", name, err))
		}
		out.Kind = &capv1.Caveat_SupervisorRequired{
			SupervisorRequired: &capv1.SupervisorRequiredCaveat{SupervisorRole: c.SupervisorRole},
		}
	case "rate_limit":
		var c caveatRateLimit
		if err := json.Unmarshal(raw, &c); err != nil {
			panic(fmt.Sprintf("[%s] caveat.rate_limit: %v", name, err))
		}
		out.Kind = &capv1.Caveat_RateLimit{
			RateLimit: &capv1.RateLimitCaveat{
				MaxActions:    c.MaxActions,
				WindowSeconds: c.WindowSeconds,
			},
		}
	case "only_if_tagged":
		var c caveatOnlyIfTagged
		if err := json.Unmarshal(raw, &c); err != nil {
			panic(fmt.Sprintf("[%s] caveat.only_if_tagged: %v", name, err))
		}
		out.Kind = &capv1.Caveat_OnlyIfTagged{
			OnlyIfTagged: &capv1.OnlyIfTaggedCaveat{RequiredTags: c.RequiredTags},
		}
	case "never_if_tagged":
		var c caveatNeverIfTagged
		if err := json.Unmarshal(raw, &c); err != nil {
			panic(fmt.Sprintf("[%s] caveat.never_if_tagged: %v", name, err))
		}
		out.Kind = &capv1.Caveat_NeverIfTagged{
			NeverIfTagged: &capv1.NeverIfTaggedCaveat{ForbiddenTags: c.ForbiddenTags},
		}
	default:
		panic(fmt.Sprintf("[%s] unknown caveat kind: %q", name, disc.Kind))
	}
	return out
}

// -----------------------------------------------------------------------------
// Fixture → proto.Capability
// -----------------------------------------------------------------------------

func buildCapability(name string, f capabilityFields) *capv1.Capability {
	scope := &capv1.Scope{
		PermittedActions:    append([]string(nil), f.Scope.PermittedActions...),
		ResourceTags:        append([]string(nil), f.Scope.ResourceTags...),
		Bounds:              f.Scope.Bounds,
		PermittedRecipients: append([]string(nil), f.Scope.PermittedRecipients...),
		MemoryScopes:        append([]string(nil), f.Scope.MemoryScopes...),
	}

	c := &capv1.Capability{
		SpecVersion:        &commonv1.Version{Value: f.SpecVersion},
		CapabilityId:       mustHex(f.CapabilityIDHex),
		SwarmId:            &commonv1.SwarmId{Value: mustHex(f.SwarmIDHex)},
		Issuer:             parseIssuer(name, f.Issuer),
		Subject:            &commonv1.AgentId{Value: mustHex(f.SubjectHex)},
		Scope:              scope,
		ValidFrom: &commonv1.Timestamp{
			WallClock:   f.ValidFrom.WallClock,
			MonotonicNs: f.ValidFrom.MonotonicNs,
		},
		ValidUntil: &commonv1.Timestamp{
			WallClock:   f.ValidUntil.WallClock,
			MonotonicNs: f.ValidUntil.MonotonicNs,
		},
		RevocationEndpoint: f.RevocationEndpoint,
	}

	if f.ParentHex != nil {
		c.Parent = &commonv1.Hash{
			Algorithm: commonv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
			Digest:    mustHex(*f.ParentHex),
		}
	}

	for _, raw := range f.Caveats {
		c.Caveats = append(c.Caveats, parseCaveat(name, raw))
	}

	return c
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

func TestCapabilityVectorsMatch(t *testing.T) {
	dir := filepath.Join(vectorsBase(t), "capability")
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
		t.Fatalf("no capability vectors found in %s", dir)
	}

	marshaler := proto.MarshalOptions{Deterministic: true}

	var failures []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: read: %v", path, err))
			continue
		}
		var v capabilityVector
		if err := json.Unmarshal(raw, &v); err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse: %v", path, err))
			continue
		}
		if v.Kind != "capability" {
			continue
		}
		msg := buildCapability(v.Name, v.Fields)
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
		t.Fatalf("%d capability vector(s) failed:\n\n%s",
			len(failures), strings.Join(failures, "\n\n"))
	}
}
