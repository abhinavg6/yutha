//! Conversions between ergonomic [`yutha-capability`](crate) types and the
//! prost-generated wire types in `yutha-proto`.
//!
//! Same pattern as the other consumer crates: ergonomic → proto, one way.
//! Used for content-addressing and signature verification through
//! [`Capability::to_canonical_proto`].
//!
//! ## Signature shape mismatch (intentional)
//!
//! The spec models `Capability.signatures` as `repeated CapabilitySignature`
//! to anticipate verifiable-tier attestations alongside the issuer signature.
//! The ergonomic Rust shape exposes a single `issuer_signature: Option<Signature>`
//! today because attestation signatures aren't wired in yet. When we convert,
//! a `Some(sig)` becomes a one-element `Vec<CapabilitySignature>` with role =
//! ISSUER; `None` becomes an empty vec. `to_canonical_proto()` clears the vec
//! anyway, so this round-trips cleanly through content-addressing.

use crate::{Capability, Caveat, ControlPlaneIssuer, Issuer, RateLimit, Scope, TimeOfDay};
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
}
