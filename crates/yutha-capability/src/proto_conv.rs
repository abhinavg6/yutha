//! Conversions between ergonomic [`yutha-capability`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! The forward direction (ergonomic → proto) is used for content-addressing
//! and signature verification through [`Capability::to_canonical_proto`].
//!
//! The reverse direction (proto → ergonomic) is used by the control-plane
//! gRPC handlers when decoding `IssueRequest`, `AttenuateRequest`, and
//! `CheckRequest` payloads. Reverse conversions are fallible because the
//! wire shape uses `Option<T>` for nested messages and unknown oneof
//! selectors are rejected up front.
//!
//! ## Signature shape mismatch (intentional)
//!
//! The spec models `Capability.signatures` as `repeated CapabilitySignature`
//! to anticipate verifiable-tier attestations alongside the issuer signature.
//! The ergonomic Rust shape exposes a single `issuer_signature: Option<Signature>`
//! today because attestation signatures aren't wired in yet. When we convert
//! forward, a `Some(sig)` becomes a one-element `Vec<CapabilitySignature>`
//! with role = ISSUER; `None` becomes an empty vec. When we convert reverse,
//! we look for a CapabilitySignature with role = ISSUER and lift its
//! signature into `issuer_signature`; any extra signatures (attestations) are
//! silently dropped today and become re-attachable when verifiable-tier work
//! lands. `to_canonical_proto()` clears the vec anyway, so this round-trips
//! cleanly through content-addressing.

use crate::{
    ActionDescriptor, Capability, CapabilityError, Caveat, CheckOutcome, ControlPlaneIssuer,
    Issuer, RateLimit, Scope, TimeOfDay,
};
use yutha_core::{AgentId, CoreError, Hash, Signature, SpecVersion, SwarmId, Timestamp};
use yutha_proto::capability::v1 as proto;
use yutha_proto::common::v1 as common;

// -----------------------------------------------------------------------------
// Issuer (oneof)
// -----------------------------------------------------------------------------

impl From<&Issuer> for proto::Issuer {
    fn from(i: &Issuer) -> Self {
        let kind = match i {
            Issuer::Agent(id) => proto::issuer::Kind::Agent(id.into()),
            Issuer::Operator(fp) => proto::issuer::Kind::OperatorKeyFingerprint(fp.clone()),
            Issuer::ControlPlane(cp) => proto::issuer::Kind::ControlPlane(cp.into()),
        };
        proto::Issuer { kind: Some(kind) }
    }
}

impl From<&ControlPlaneIssuer> for proto::ControlPlaneIssuer {
    fn from(c: &ControlPlaneIssuer) -> Self {
        proto::ControlPlaneIssuer {
            control_plane_key_fingerprint: c.control_plane_key_fingerprint.clone(),
            instance_id: c.instance_id.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Scope
// -----------------------------------------------------------------------------

impl From<&Scope> for proto::Scope {
    fn from(s: &Scope) -> Self {
        proto::Scope {
            permitted_actions: s.permitted_actions.clone(),
            resource_tags: s.resource_tags.clone(),
            // `bounds` is generated as `BTreeMap<String, String>` via
            // btree_map(["."]) in yutha-proto/build.rs — sorted-key encoding
            // for free.
            bounds: s.bounds.clone(),
            permitted_recipients: s.permitted_recipients.clone(),
            memory_scopes: s.memory_scopes.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Caveat (oneof)
// -----------------------------------------------------------------------------

impl From<&TimeOfDay> for proto::TimeOfDayCaveat {
    fn from(t: &TimeOfDay) -> Self {
        proto::TimeOfDayCaveat {
            from_utc: t.from_utc.clone(),
            to_utc: t.to_utc.clone(),
        }
    }
}

impl From<&RateLimit> for proto::RateLimitCaveat {
    fn from(r: &RateLimit) -> Self {
        proto::RateLimitCaveat {
            max_actions: r.max_actions,
            window_seconds: r.window_seconds,
        }
    }
}

impl From<&Caveat> for proto::Caveat {
    fn from(c: &Caveat) -> Self {
        let kind = match c {
            Caveat::TimeOfDay(t) => proto::caveat::Kind::TimeOfDay(t.into()),
            Caveat::ConstitutionVersion {
                min_version,
                max_version,
            } => proto::caveat::Kind::ConstitutionVersion(proto::ConstitutionVersionCaveat {
                min_version: min_version.clone(),
                // Spec field is non-optional string; empty = no upper bound.
                max_version: max_version.clone().unwrap_or_default(),
            }),
            Caveat::SupervisorRequired { supervisor_role } => {
                proto::caveat::Kind::SupervisorRequired(proto::SupervisorRequiredCaveat {
                    supervisor_role: supervisor_role.clone(),
                })
            }
            Caveat::RateLimit(r) => proto::caveat::Kind::RateLimit(r.into()),
            Caveat::OnlyIfTagged { required_tags } => {
                proto::caveat::Kind::OnlyIfTagged(proto::OnlyIfTaggedCaveat {
                    required_tags: required_tags.clone(),
                })
            }
            Caveat::NeverIfTagged { forbidden_tags } => {
                proto::caveat::Kind::NeverIfTagged(proto::NeverIfTaggedCaveat {
                    forbidden_tags: forbidden_tags.clone(),
                })
            }
        };
        proto::Caveat { kind: Some(kind) }
    }
}

// -----------------------------------------------------------------------------
// Capability
// -----------------------------------------------------------------------------

impl From<&Capability> for proto::Capability {
    fn from(c: &Capability) -> Self {
        let signatures = match &c.issuer_signature {
            None => Vec::new(),
            Some(sig) => vec![proto::CapabilitySignature {
                role: proto::CapabilitySignatureRole::Issuer as i32,
                signature: Some(sig.into()),
                // Rust shape doesn't carry signed_at separately; canonical
                // bytes don't include signatures anyway, so a zero
                // timestamp is harmless for content-addressing. Constructed
                // directly as a proto value (skipping ergonomic Timestamp,
                // which validates RFC 3339).
                signed_at: Some(common::Timestamp {
                    wall_clock: String::new(),
                    monotonic_ns: 0,
                }),
            }],
        };

        proto::Capability {
            spec_version: Some((&c.spec_version).into()),
            capability_id: c.capability_id.clone(),
            swarm_id: Some((&c.swarm_id).into()),
            issuer: Some((&c.issuer).into()),
            subject: Some((&c.subject).into()),
            scope: Some((&c.scope).into()),
            parent: c.parent.as_ref().map(Into::into),
            valid_from: Some((&c.valid_from).into()),
            valid_until: Some((&c.valid_until).into()),
            caveats: c.caveats.iter().map(Into::into).collect(),
            revocation_endpoint: c.revocation_endpoint.clone(),
            extensions: None,
            signatures,
        }
    }
}

impl Capability {
    /// Canonical proto representation for content-addressing and signature.
    ///
    /// Clears `signatures` (the field whose canonical bytes are what
    /// signatures sign — including them would be circular) and drops
    /// `extensions` (vendor extensions don't participate in
    /// content-addressing at v1.0).
    pub fn to_canonical_proto(&self) -> proto::Capability {
        let mut c: proto::Capability = self.into();
        c.signatures.clear();
        c.extensions = None;
        c
    }
}

// =============================================================================
// REVERSE: proto → ergonomic
// =============================================================================

/// Helper: structured "required field missing" error mapped to
/// `INVALID_ARGUMENT` at the gRPC layer via the
/// `CapabilityError::Core` → `CoreError::Validation` chain.
fn missing(field: &'static str) -> CapabilityError {
    CapabilityError::Core(CoreError::validation(format!(
        "required field missing: {field}"
    )))
}

// -----------------------------------------------------------------------------
// ControlPlaneIssuer
// -----------------------------------------------------------------------------

impl From<&proto::ControlPlaneIssuer> for ControlPlaneIssuer {
    fn from(p: &proto::ControlPlaneIssuer) -> Self {
        ControlPlaneIssuer {
            control_plane_key_fingerprint: p.control_plane_key_fingerprint.clone(),
            instance_id: p.instance_id.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Issuer (oneof)
// -----------------------------------------------------------------------------

impl TryFrom<&proto::Issuer> for Issuer {
    type Error = CapabilityError;
    fn try_from(p: &proto::Issuer) -> Result<Self, Self::Error> {
        use proto::issuer::Kind;
        let kind = p.kind.as_ref().ok_or_else(|| missing("issuer.kind"))?;
        Ok(match kind {
            Kind::Agent(id) => Issuer::Agent(AgentId::try_from(id)?),
            Kind::OperatorKeyFingerprint(bytes) => Issuer::Operator(bytes.clone()),
            Kind::ControlPlane(cp) => Issuer::ControlPlane(cp.into()),
        })
    }
}

// -----------------------------------------------------------------------------
// Scope
// -----------------------------------------------------------------------------

impl From<&proto::Scope> for Scope {
    /// Scope is plain scalars and collections — infallible. (`bounds` is a
    /// `BTreeMap<String, String>` via `btree_map(["."])` configuration so
    /// sorted-key encoding is preserved through round-trip.)
    fn from(p: &proto::Scope) -> Self {
        Scope {
            permitted_actions: p.permitted_actions.clone(),
            resource_tags: p.resource_tags.clone(),
            bounds: p.bounds.clone(),
            permitted_recipients: p.permitted_recipients.clone(),
            memory_scopes: p.memory_scopes.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Caveat sub-types
// -----------------------------------------------------------------------------

impl From<&proto::TimeOfDayCaveat> for TimeOfDay {
    fn from(p: &proto::TimeOfDayCaveat) -> Self {
        TimeOfDay {
            from_utc: p.from_utc.clone(),
            to_utc: p.to_utc.clone(),
        }
    }
}

impl From<&proto::RateLimitCaveat> for RateLimit {
    fn from(p: &proto::RateLimitCaveat) -> Self {
        RateLimit {
            max_actions: p.max_actions,
            window_seconds: p.window_seconds,
        }
    }
}

impl TryFrom<&proto::Caveat> for Caveat {
    type Error = CapabilityError;
    fn try_from(p: &proto::Caveat) -> Result<Self, Self::Error> {
        use proto::caveat::Kind;
        let kind = p.kind.as_ref().ok_or_else(|| missing("caveat.kind"))?;
        Ok(match kind {
            Kind::TimeOfDay(t) => Caveat::TimeOfDay(t.into()),
            Kind::ConstitutionVersion(v) => Caveat::ConstitutionVersion {
                min_version: v.min_version.clone(),
                // Empty string on the wire = no upper bound (see forward
                // conversion); preserve that semantic on the way back.
                max_version: if v.max_version.is_empty() {
                    None
                } else {
                    Some(v.max_version.clone())
                },
            },
            Kind::SupervisorRequired(s) => Caveat::SupervisorRequired {
                supervisor_role: s.supervisor_role.clone(),
            },
            Kind::RateLimit(r) => Caveat::RateLimit(r.into()),
            Kind::OnlyIfTagged(o) => Caveat::OnlyIfTagged {
                required_tags: o.required_tags.clone(),
            },
            Kind::NeverIfTagged(n) => Caveat::NeverIfTagged {
                forbidden_tags: n.forbidden_tags.clone(),
            },
        })
    }
}

// -----------------------------------------------------------------------------
// Capability
// -----------------------------------------------------------------------------

impl TryFrom<&proto::Capability> for Capability {
    type Error = CapabilityError;

    /// Decode a `proto::Capability` into the ergonomic [`Capability`].
    ///
    /// Signature handling (see module-level note): we look for an
    /// ISSUER-role entry in `signatures`; if found, lift its signature
    /// into `issuer_signature`. Extra signatures (future attestation
    /// roles) are dropped silently — round-tripping back through the
    /// forward conversion will re-emit only the issuer signature.
    ///
    /// Does NOT verify the issuer signature. Caller is responsible for
    /// running that check (or letting the `CapabilityStore` reject on
    /// `issue`/`attenuate`).
    fn try_from(p: &proto::Capability) -> Result<Self, Self::Error> {
        let spec_version = SpecVersion::try_from(
            p.spec_version
                .as_ref()
                .ok_or_else(|| missing("spec_version"))?,
        )?;
        let swarm_id = SwarmId::try_from(p.swarm_id.as_ref().ok_or_else(|| missing("swarm_id"))?)?;
        let issuer = Issuer::try_from(p.issuer.as_ref().ok_or_else(|| missing("issuer"))?)?;
        let subject = AgentId::try_from(p.subject.as_ref().ok_or_else(|| missing("subject"))?)?;
        let scope = p
            .scope
            .as_ref()
            .map(Scope::from)
            .unwrap_or_else(Scope::empty);
        let parent = p.parent.as_ref().map(Hash::try_from).transpose()?;
        let valid_from =
            Timestamp::try_from(p.valid_from.as_ref().ok_or_else(|| missing("valid_from"))?)?;
        let valid_until = Timestamp::try_from(
            p.valid_until
                .as_ref()
                .ok_or_else(|| missing("valid_until"))?,
        )?;
        let caveats = p
            .caveats
            .iter()
            .map(Caveat::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        // Find the issuer-role signature (if any); ignore other roles.
        let issuer_signature = p
            .signatures
            .iter()
            .find(|s| s.role == proto::CapabilitySignatureRole::Issuer as i32)
            .and_then(|s| s.signature.as_ref())
            .map(Signature::try_from)
            .transpose()?;

        Ok(Capability {
            spec_version,
            capability_id: p.capability_id.clone(),
            swarm_id,
            issuer,
            subject,
            scope,
            parent,
            valid_from,
            valid_until,
            caveats,
            revocation_endpoint: p.revocation_endpoint.clone(),
            issuer_signature,
        })
    }
}

// -----------------------------------------------------------------------------
// ActionDescriptor (both directions — used in CheckRequest)
// -----------------------------------------------------------------------------

impl From<&ActionDescriptor> for proto::ActionDescriptor {
    fn from(d: &ActionDescriptor) -> Self {
        proto::ActionDescriptor {
            action_kind: d.action_kind.clone(),
            resource_tags: d.resource_tags.clone(),
            numeric_values: d.numeric_values.clone(),
            recipient: d.recipient.clone().unwrap_or_default(),
            memory_scope: d.memory_scope.clone().unwrap_or_default(),
        }
    }
}

impl From<&proto::ActionDescriptor> for ActionDescriptor {
    fn from(p: &proto::ActionDescriptor) -> Self {
        // Empty strings on the wire map back to None for the optional
        // ergonomic fields — preserves the "absent" vs. "empty-string"
        // distinction the ergonomic type cares about.
        ActionDescriptor {
            action_kind: p.action_kind.clone(),
            resource_tags: p.resource_tags.clone(),
            numeric_values: p.numeric_values.clone(),
            recipient: if p.recipient.is_empty() {
                None
            } else {
                Some(p.recipient.clone())
            },
            memory_scope: if p.memory_scope.is_empty() {
                None
            } else {
                Some(p.memory_scope.clone())
            },
        }
    }
}

// -----------------------------------------------------------------------------
// CheckOutcome → CheckResponse
// -----------------------------------------------------------------------------

impl CheckOutcome {
    /// Encode for the wire. The `check_receipt` field is left for the
    /// caller to fill in — the receipt is produced by the
    /// [`CapabilityStore::check`](crate::CapabilityStore::check)
    /// path, not the outcome itself.
    pub fn to_proto_with_receipt(&self, check_receipt: Option<&Hash>) -> proto::CheckResponse {
        proto::CheckResponse {
            permitted: self.permitted,
            deny_reason: self.deny_reason.clone(),
            matched_caveats: self.matched_caveats.clone(),
            unmet_caveats: self.unmet_caveats.clone(),
            check_receipt: check_receipt.map(Into::into),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capability, Caveat, Issuer, Scope};
    use yutha_core::{AgentId, SpecVersion, SwarmId, Timestamp};
    use yutha_crypto::sign::generate_keypair;
    use yutha_proto::Message;

    fn signed_fixture() -> Capability {
        let key = generate_keypair();
        Capability::builder()
            .spec_version(SpecVersion::parse("1.0.0").unwrap())
            .capability_id(vec![0u8; 16])
            .swarm_id(SwarmId::new())
            .issuer(Issuer::Agent(AgentId::new()))
            .subject(AgentId::new())
            .scope(
                Scope::for_action("issue_refund")
                    .with_tag("finance")
                    .with_bound("usd_max", "500.00"),
            )
            .valid_from(Timestamp::now())
            .valid_until(Timestamp::new("2099-01-01T00:00:00Z".into(), u64::MAX / 2).unwrap())
            .caveat(Caveat::NeverIfTagged {
                forbidden_tags: vec!["external".into()],
            })
            .sign(&key)
            .unwrap()
    }

    #[test]
    fn capability_round_trips_to_proto() {
        let c = signed_fixture();
        let p: proto::Capability = (&c).into();
        assert_eq!(p.capability_id, vec![0u8; 16]);
        assert_eq!(p.signatures.len(), 1, "issuer signature in vec");
        assert_eq!(
            p.signatures[0].role,
            proto::CapabilitySignatureRole::Issuer as i32
        );
        assert!(p.scope.is_some());
        assert_eq!(p.caveats.len(), 1);
    }

    #[test]
    fn canonical_proto_clears_signatures_and_extensions() {
        let c = signed_fixture();
        let cp = c.to_canonical_proto();
        assert!(cp.signatures.is_empty(), "signatures cleared");
        assert!(cp.extensions.is_none(), "extensions cleared");
        assert_eq!(cp.capability_id, vec![0u8; 16], "other fields survive");
    }

    #[test]
    fn canonical_encoding_is_bytewise_deterministic() {
        let c = signed_fixture();
        let a = c.to_canonical_proto().encode_to_vec();
        let b = c.to_canonical_proto().encode_to_vec();
        let d = c.clone().to_canonical_proto().encode_to_vec();
        assert_eq!(a, b);
        assert_eq!(a, d);
    }

    #[test]
    fn issuer_oneof_handles_all_three_variants() {
        for issuer in [
            Issuer::Agent(AgentId::new()),
            Issuer::Operator(vec![0xab; 32]),
            Issuer::ControlPlane(ControlPlaneIssuer {
                control_plane_key_fingerprint: vec![0xcd; 32],
                instance_id: "cp-test-1".into(),
            }),
        ] {
            let p: proto::Issuer = (&issuer).into();
            assert!(p.kind.is_some(), "oneof must be set");
        }
    }

    #[test]
    fn caveat_oneof_handles_all_six_variants() {
        for caveat in [
            Caveat::TimeOfDay(TimeOfDay {
                from_utc: "09:00".into(),
                to_utc: "17:00".into(),
            }),
            Caveat::ConstitutionVersion {
                min_version: "1.0.0".into(),
                max_version: Some("1.4.0".into()),
            },
            Caveat::SupervisorRequired {
                supervisor_role: "approver".into(),
            },
            Caveat::RateLimit(RateLimit {
                max_actions: 10,
                window_seconds: 60,
            }),
            Caveat::OnlyIfTagged {
                required_tags: vec!["pii".into()],
            },
            Caveat::NeverIfTagged {
                forbidden_tags: vec!["external".into()],
            },
        ] {
            let p: proto::Caveat = (&caveat).into();
            assert!(p.kind.is_some(), "caveat oneof must be set for {caveat:?}");
        }
    }

    // -------------------------------------------------------------------------
    // Reverse conversion tests (proto → ergonomic)
    // -------------------------------------------------------------------------

    #[test]
    fn capability_round_trips_proto_to_ergonomic() {
        let original = signed_fixture();
        let p: proto::Capability = (&original).into();
        let back = Capability::try_from(&p).expect("reverse should succeed");

        assert_eq!(back.capability_id, original.capability_id);
        assert_eq!(back.swarm_id, original.swarm_id);
        assert_eq!(back.subject, original.subject);
        assert_eq!(
            back.scope.permitted_actions,
            original.scope.permitted_actions
        );
        assert_eq!(back.caveats.len(), original.caveats.len());
        assert_eq!(
            back.issuer_signature.is_some(),
            original.issuer_signature.is_some(),
            "issuer signature lifts back into Option"
        );
    }

    #[test]
    fn capability_missing_issuer_rejected() {
        let c = signed_fixture();
        let mut p: proto::Capability = (&c).into();
        p.issuer = None;
        let err = Capability::try_from(&p).unwrap_err();
        assert!(matches!(err, CapabilityError::Core(_)));
        assert!(err.to_string().contains("issuer"));
    }

    #[test]
    fn issuer_oneof_reverse_handles_all_three_variants() {
        for issuer in [
            Issuer::Agent(AgentId::new()),
            Issuer::Operator(vec![0xab; 32]),
            Issuer::ControlPlane(ControlPlaneIssuer {
                control_plane_key_fingerprint: vec![0xcd; 32],
                instance_id: "cp-test-1".into(),
            }),
        ] {
            let p: proto::Issuer = (&issuer).into();
            let back = Issuer::try_from(&p).unwrap();
            assert_eq!(back, issuer);
        }
    }

    #[test]
    fn issuer_missing_oneof_rejected() {
        let p = proto::Issuer { kind: None };
        let err = Issuer::try_from(&p).unwrap_err();
        assert!(matches!(err, CapabilityError::Core(_)));
    }

    #[test]
    fn caveat_oneof_reverse_handles_all_six_variants() {
        let cases = [
            Caveat::TimeOfDay(TimeOfDay {
                from_utc: "09:00".into(),
                to_utc: "17:00".into(),
            }),
            Caveat::ConstitutionVersion {
                min_version: "1.0.0".into(),
                max_version: Some("1.4.0".into()),
            },
            Caveat::ConstitutionVersion {
                min_version: "1.0.0".into(),
                max_version: None, // empty-string-on-wire → None
            },
            Caveat::SupervisorRequired {
                supervisor_role: "approver".into(),
            },
            Caveat::RateLimit(RateLimit {
                max_actions: 10,
                window_seconds: 60,
            }),
            Caveat::OnlyIfTagged {
                required_tags: vec!["pii".into()],
            },
            Caveat::NeverIfTagged {
                forbidden_tags: vec!["external".into()],
            },
        ];
        for caveat in cases {
            let p: proto::Caveat = (&caveat).into();
            let back = Caveat::try_from(&p).unwrap();
            assert_eq!(back, caveat, "round-trip mismatch for {caveat:?}");
        }
    }

    #[test]
    fn action_descriptor_round_trips() {
        let mut numeric = std::collections::BTreeMap::new();
        numeric.insert("usd".into(), "100.00".into());
        let original = ActionDescriptor {
            action_kind: "issue_refund".into(),
            resource_tags: vec!["finance".into(), "customer".into()],
            numeric_values: numeric,
            recipient: Some("acct-123".into()),
            memory_scope: Some("private".into()),
        };
        let p: proto::ActionDescriptor = (&original).into();
        let back: ActionDescriptor = (&p).into();
        assert_eq!(back.action_kind, original.action_kind);
        assert_eq!(back.resource_tags, original.resource_tags);
        assert_eq!(back.numeric_values, original.numeric_values);
        assert_eq!(back.recipient, original.recipient);
        assert_eq!(back.memory_scope, original.memory_scope);
    }

    #[test]
    fn action_descriptor_empty_strings_decode_to_none() {
        let p = proto::ActionDescriptor {
            action_kind: "x".into(),
            resource_tags: vec![],
            numeric_values: std::collections::BTreeMap::new(),
            recipient: String::new(),
            memory_scope: String::new(),
        };
        let back: ActionDescriptor = (&p).into();
        assert_eq!(back.recipient, None);
        assert_eq!(back.memory_scope, None);
    }
}
