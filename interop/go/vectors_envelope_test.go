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
	envelopev1 "github.com/yutha/yutha/interop/go/gen/yutha/envelope/v1"
)

// -----------------------------------------------------------------------------
// Fixture schema — mirrors crates/yutha-transport/tests/vectors.rs
// -----------------------------------------------------------------------------

type envelopeVector struct {
	Name                 string         `json:"name"`
	Description          string         `json:"description"`
	Kind                 string         `json:"kind"`
	Fields               envelopeFields `json:"fields"`
	ExpectedCanonicalHex string         `json:"expected_canonical_hex"`
}

type envelopeFields struct {
	SpecVersion       string           `json:"spec_version"`
	SwarmIDHex        string           `json:"swarm_id_hex"`
	EnvelopeIDHex     string           `json:"envelope_id_hex"`
	FromAgentHex      string           `json:"from_agent_hex"`
	Recipient         json.RawMessage  `json:"recipient"`
	Performative      string           `json:"performative"`
	PayloadHex        string           `json:"payload_hex"`
	PayloadSchemaID   string           `json:"payload_schema_id"`
	Tags              []string         `json:"tags"`
	PredecessorsHex   []string         `json:"predecessors_hex"`
	NonceHex          string           `json:"nonce_hex"`
	Epoch             uint64           `json:"epoch"`
	SentAt            timestampFields  `json:"sent_at"`
	ExpiresAt         *timestampFields `json:"expires_at"`
	InReplyToHex      *string          `json:"in_reply_to_hex"`
}

// recipientDiscriminator peels the `kind` tag off the recipient object so
// we can dispatch on it. Each variant has its own concrete shape decoded
// below.
type recipientDiscriminator struct {
	Kind string `json:"kind"`
}

type recipientAgent struct {
	Kind     string `json:"kind"`
	AgentHex string `json:"agent_hex"`
}

type recipientRole struct {
	Kind string `json:"kind"`
	Role string `json:"role"`
}

type recipientSwarm struct {
	Kind       string   `json:"kind"`
	FilterTags []string `json:"filter_tags"`
}

type recipientExternal struct {
	Kind      string `json:"kind"`
	Scheme    string `json:"scheme"`
	Authority string `json:"authority"`
	PathHint  string `json:"path_hint"`
}

// -----------------------------------------------------------------------------
// Parse helpers
// -----------------------------------------------------------------------------

func parsePerformative(s string) envelopev1.Performative {
	switch s {
	case "propose":
		return envelopev1.Performative_PERFORMATIVE_PROPOSE
	case "counter":
		return envelopev1.Performative_PERFORMATIVE_COUNTER
	case "commit":
		return envelopev1.Performative_PERFORMATIVE_COMMIT
	case "abort":
		return envelopev1.Performative_PERFORMATIVE_ABORT
	case "release":
		return envelopev1.Performative_PERFORMATIVE_RELEASE
	case "query":
		return envelopev1.Performative_PERFORMATIVE_QUERY
	case "inform":
		return envelopev1.Performative_PERFORMATIVE_INFORM
	case "error":
		return envelopev1.Performative_PERFORMATIVE_ERROR
	case "request_action":
		return envelopev1.Performative_PERFORMATIVE_REQUEST_ACTION
	case "confirm":
		return envelopev1.Performative_PERFORMATIVE_CONFIRM
	case "decline":
		return envelopev1.Performative_PERFORMATIVE_DECLINE
	default:
		panic(fmt.Sprintf("unknown performative: %q", s))
	}
}

func parseRecipient(name string, raw json.RawMessage) *envelopev1.Recipient {
	var disc recipientDiscriminator
	if err := json.Unmarshal(raw, &disc); err != nil {
		panic(fmt.Sprintf("[%s] recipient: %v", name, err))
	}

	r := &envelopev1.Recipient{}
	switch disc.Kind {
	case "agent":
		var a recipientAgent
		if err := json.Unmarshal(raw, &a); err != nil {
			panic(fmt.Sprintf("[%s] recipient.agent: %v", name, err))
		}
		r.To = &envelopev1.Recipient_Agent{
			Agent: &commonv1.AgentId{Value: mustHex(a.AgentHex)},
		}
	case "role":
		var role recipientRole
		if err := json.Unmarshal(raw, &role); err != nil {
			panic(fmt.Sprintf("[%s] recipient.role: %v", name, err))
		}
		r.To = &envelopev1.Recipient_Role{Role: role.Role}
	case "swarm":
		var sw recipientSwarm
		if err := json.Unmarshal(raw, &sw); err != nil {
			panic(fmt.Sprintf("[%s] recipient.swarm: %v", name, err))
		}
		r.To = &envelopev1.Recipient_Swarm{
			Swarm: &envelopev1.SwarmBroadcast{FilterTags: sw.FilterTags},
		}
	case "external":
		var ex recipientExternal
		if err := json.Unmarshal(raw, &ex); err != nil {
			panic(fmt.Sprintf("[%s] recipient.external: %v", name, err))
		}
		r.To = &envelopev1.Recipient_External{
			External: &envelopev1.ExternalEndpoint{
				Scheme:    ex.Scheme,
				Authority: ex.Authority,
				PathHint:  ex.PathHint,
			},
		}
	default:
		panic(fmt.Sprintf("[%s] unknown recipient kind: %q", name, disc.Kind))
	}
	return r
}

// -----------------------------------------------------------------------------
// Fixture → proto.Envelope
// -----------------------------------------------------------------------------

func buildEnvelope(name string, f envelopeFields) *envelopev1.Envelope {
	causal := &commonv1.CausalRef{
		Predecessors: make([]*commonv1.Hash, 0, len(f.PredecessorsHex)),
	}
	for _, h := range f.PredecessorsHex {
		causal.Predecessors = append(causal.Predecessors, &commonv1.Hash{
			Algorithm: commonv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
			Digest:    mustHex(h),
		})
	}

	e := &envelopev1.Envelope{
		SpecVersion:     &commonv1.Version{Value: f.SpecVersion},
		SwarmId:         &commonv1.SwarmId{Value: mustHex(f.SwarmIDHex)},
		EnvelopeId:      mustHex(f.EnvelopeIDHex),
		FromAgent:       &commonv1.AgentId{Value: mustHex(f.FromAgentHex)},
		Recipient:       parseRecipient(name, f.Recipient),
		Performative:    parsePerformative(f.Performative),
		Payload:         mustHex(f.PayloadHex),
		PayloadSchemaId: f.PayloadSchemaID,
		Tags:            append([]string(nil), f.Tags...),
		Causal:          causal,
		Nonce:           mustHex(f.NonceHex),
		Epoch:           f.Epoch,
		SentAt: &commonv1.Timestamp{
			WallClock:   f.SentAt.WallClock,
			MonotonicNs: f.SentAt.MonotonicNs,
		},
	}

	if f.ExpiresAt != nil {
		e.ExpiresAt = &commonv1.Timestamp{
			WallClock:   f.ExpiresAt.WallClock,
			MonotonicNs: f.ExpiresAt.MonotonicNs,
		}
	}

	if f.InReplyToHex != nil {
		e.InReplyTo = &commonv1.Hash{
			Algorithm: commonv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
			Digest:    mustHex(*f.InReplyToHex),
		}
	}

	return e
}

// -----------------------------------------------------------------------------
// Test driver
// -----------------------------------------------------------------------------

func TestEnvelopeVectorsMatch(t *testing.T) {
	dir := filepath.Join(vectorsBase(t), "envelope")
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
		t.Fatalf("no envelope vectors found in %s", dir)
	}

	marshaler := proto.MarshalOptions{Deterministic: true}

	var failures []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: read: %v", path, err))
			continue
		}
		var v envelopeVector
		if err := json.Unmarshal(raw, &v); err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse: %v", path, err))
			continue
		}
		if v.Kind != "envelope" {
			continue
		}
		msg := buildEnvelope(v.Name, v.Fields)
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
		t.Fatalf("%d envelope vector(s) failed:\n\n%s",
			len(failures), strings.Join(failures, "\n\n"))
	}
}
