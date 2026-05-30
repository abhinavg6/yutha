//! Error mapping: yutha library errors → `tonic::Status`.
//!
//! Every handler that calls into the in-process backends receives a
//! `Result<_, SomeYuthaError>`. This module defines a local
//! [`ErrorIntoStatus`] trait and implements it for each library error,
//! so handlers can write:
//!
//! ```ignore
//! self.state.registry.register(passport)
//!     .await
//!     .map_err(|e| e.to_status())?;
//! ```
//!
//! ## Why a trait instead of `From`?
//!
//! Both `From` and `tonic::Status` are foreign types, and so are the
//! library error enums. Rust's orphan rule forbids `impl From<&FooErr>
//! for Status` from this crate. Defining a local trait sidesteps the
//! rule entirely while keeping the call sites just as ergonomic.
//!
//! ## Code-selection rules
//!
//! - **`invalid_argument`** — the request was structurally bad (wrong
//!   length, unknown enum, unparseable timestamp). Things the client
//!   should not retry without modification.
//! - **`unauthenticated`** — bearer token missing, expired, or signed
//!   by a key the resolver doesn't know.
//! - **`permission_denied`** — capability denied, admission denied,
//!   caveat unmet, scope violated.
//! - **`not_found`** — receipt/capability/agent looked up by id that
//!   doesn't exist.
//! - **`already_exists`** — re-register of an agent_id.
//! - **`failed_precondition`** — out-of-window capability, sybil check
//!   failed, append-only violation, signature-order rule broken.
//! - **`resource_exhausted`** — transport backpressure.
//! - **`deadline_exceeded`** — transport timeout, envelope expired.
//! - **`internal`** — backend I/O failure, control-plane bug. Includes
//!   the underlying error in the message so operators can correlate;
//!   should never leak secrets because nothing in the backend errors
//!   carries any.
//!
//! Reference: <https://grpc.io/docs/guides/status-codes/>

use tonic::Status;

use yutha_capability::CapabilityError;
use yutha_core::CoreError;
use yutha_passport::PassportError;
use yutha_receipt::ReceiptError;
use yutha_registry::RegistryError;
use yutha_transport::TransportError;

/// Locally-defined trait that lets us map foreign error types to the
/// foreign `tonic::Status` from this crate without running into the
/// orphan rule. Implemented for every yutha-* error enum.
pub trait ErrorIntoStatus {
    /// Map this error to the most semantically appropriate
    /// `tonic::Status`. Takes `&self` so the caller can log or chain
    /// the original error afterwards.
    fn to_status(&self) -> Status;
}

// -----------------------------------------------------------------------------
// CoreError
// -----------------------------------------------------------------------------

impl ErrorIntoStatus for CoreError {
    fn to_status(&self) -> Status {
        // Every CoreError variant is a structural / validation failure —
        // bad bytes-from-the-wire. The client must change the request to
        // succeed; that's `invalid_argument`.
        Status::invalid_argument(self.to_string())
    }
}

// -----------------------------------------------------------------------------
// ReceiptError
// -----------------------------------------------------------------------------

impl ErrorIntoStatus for ReceiptError {
    fn to_status(&self) -> Status {
        match self {
            ReceiptError::ContentAddressMismatch { .. }
            | ReceiptError::SignatureFailed { .. }
            | ReceiptError::SignatureOrderInvalid { .. }
            | ReceiptError::MissingSignatureRole { .. } => {
                Status::failed_precondition(self.to_string())
            }
            ReceiptError::AppendOnly => Status::failed_precondition(self.to_string()),
            ReceiptError::NotFound(_) => Status::not_found(self.to_string()),
            ReceiptError::ActorNotResolvable(_) => Status::unauthenticated(self.to_string()),
            ReceiptError::PassportResolver(_) => Status::internal(self.to_string()),
            ReceiptError::InvalidQuery(_) => Status::invalid_argument(self.to_string()),
            ReceiptError::Backend(_) => Status::internal(self.to_string()),
            ReceiptError::Crypto(_) => Status::internal(self.to_string()),
            // BatchInvalid surfaces from the H2 Sealer path when the
            // canonical preimage doesn't match the receipts (sum != count,
            // histogram-key sort/length violation, etc.). It's a
            // validation failure on the batch as supplied — invalid_argument.
            ReceiptError::BatchInvalid(_) => Status::invalid_argument(self.to_string()),
            ReceiptError::Core(c) => c.to_status(),
        }
    }
}

// -----------------------------------------------------------------------------
// PassportError
// -----------------------------------------------------------------------------

impl ErrorIntoStatus for PassportError {
    fn to_status(&self) -> Status {
        match self {
            PassportError::SelfSignatureInvalid => Status::unauthenticated(self.to_string()),
            PassportError::MissingField(_) => Status::invalid_argument(self.to_string()),
            PassportError::Expired => Status::failed_precondition(self.to_string()),
            PassportError::AlreadyRegistered(_) => Status::already_exists(self.to_string()),
            PassportError::NotFound(_) => Status::not_found(self.to_string()),
            PassportError::RotationContinuityMissing => Status::unauthenticated(self.to_string()),
            PassportError::Backend(_) => Status::internal(self.to_string()),
            PassportError::Crypto(_) => Status::internal(self.to_string()),
            PassportError::Signer(_) => Status::internal(self.to_string()),
            PassportError::Core(c) => c.to_status(),
        }
    }
}

// -----------------------------------------------------------------------------
// CapabilityError
// -----------------------------------------------------------------------------

impl ErrorIntoStatus for CapabilityError {
    fn to_status(&self) -> Status {
        match self {
            CapabilityError::IssuerSignatureInvalid => Status::unauthenticated(self.to_string()),
            CapabilityError::MissingField(_) => Status::invalid_argument(self.to_string()),
            CapabilityError::OutOfValidityWindow => Status::failed_precondition(self.to_string()),
            CapabilityError::ChainTooDeep { .. } => Status::failed_precondition(self.to_string()),
            CapabilityError::AttenuationBroadens { .. } => {
                Status::permission_denied(self.to_string())
            }
            CapabilityError::ParentNotFound(_) => Status::not_found(self.to_string()),
            CapabilityError::Revoked => Status::permission_denied(self.to_string()),
            // RFC 0013 §4.2: issuance / attenuation refusal because
            // the subject is quarantined. Surface as PERMISSION_DENIED
            // — the client is correctly authenticated; the swarm
            // simply refuses to hand fresh authority to a quarantined
            // agent.
            CapabilityError::SubjectQuarantined(_) => Status::permission_denied(self.to_string()),
            CapabilityError::Backend(_) => Status::internal(self.to_string()),
            CapabilityError::Crypto(_) => Status::internal(self.to_string()),
            CapabilityError::Signer(_) => Status::internal(self.to_string()),
            CapabilityError::Core(c) => c.to_status(),
        }
    }
}

// -----------------------------------------------------------------------------
// TransportError
// -----------------------------------------------------------------------------

impl ErrorIntoStatus for TransportError {
    fn to_status(&self) -> Status {
        match self {
            TransportError::EnvelopeRejected(_) => Status::invalid_argument(self.to_string()),
            TransportError::Delivery(_) => Status::internal(self.to_string()),
            TransportError::Timeout => Status::deadline_exceeded(self.to_string()),
            TransportError::Backpressure => Status::resource_exhausted(self.to_string()),
            TransportError::Backend(_) => Status::internal(self.to_string()),
            TransportError::Receipt(r) => r.to_status(),
            TransportError::Crypto(_) => Status::internal(self.to_string()),
            TransportError::Core(c) => c.to_status(),
        }
    }
}

// -----------------------------------------------------------------------------
// RegistryError
// -----------------------------------------------------------------------------

impl ErrorIntoStatus for RegistryError {
    fn to_status(&self) -> Status {
        match self {
            RegistryError::TopologyInconsistent => Status::internal(self.to_string()),
            RegistryError::AdmissionDenied(_) => Status::permission_denied(self.to_string()),
            RegistryError::SybilCheckFailed(_) => Status::failed_precondition(self.to_string()),
            RegistryError::SwarmMismatch { .. } => Status::failed_precondition(self.to_string()),
            RegistryError::TopologyImmutable => Status::failed_precondition(self.to_string()),
            RegistryError::Passport(p) => p.to_status(),
            RegistryError::Receipt(r) => r.to_status(),
            RegistryError::Core(c) => c.to_status(),
            RegistryError::Backend(_) => Status::internal(self.to_string()),
        }
    }
}

// -----------------------------------------------------------------------------
// Convenience: "required proto field was None"
// -----------------------------------------------------------------------------

/// proto3 nested-message fields are `Option<T>` on the wire; ergonomic
/// types treat them as required. This helper standardizes the error
/// message and the gRPC code for "you didn't fill in this field."
///
/// ```ignore
/// let passport_proto = request.passport
///     .ok_or_else(|| missing_field("passport"))?;
/// ```
pub fn missing_field(name: &'static str) -> Status {
    Status::invalid_argument(format!("required field missing: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn core_invalid_length_maps_to_invalid_argument() {
        let err = CoreError::InvalidLength {
            expected: 16,
            actual: 17,
        };
        assert_eq!(err.to_status().code(), Code::InvalidArgument);
    }

    #[test]
    fn receipt_not_found_maps_to_not_found() {
        let h = yutha_core::Hash::new(yutha_core::HashAlgorithm::Sha256, vec![0u8; 32]).unwrap();
        let err = ReceiptError::NotFound(h);
        assert_eq!(err.to_status().code(), Code::NotFound);
    }

    #[test]
    fn passport_already_registered_maps_to_already_exists() {
        let err = PassportError::AlreadyRegistered(yutha_core::AgentId::new());
        assert_eq!(err.to_status().code(), Code::AlreadyExists);
    }

    #[test]
    fn registry_admission_denied_maps_to_permission_denied() {
        let err = RegistryError::AdmissionDenied("test".into());
        assert_eq!(err.to_status().code(), Code::PermissionDenied);
    }

    #[test]
    fn transport_backpressure_maps_to_resource_exhausted() {
        let err = TransportError::Backpressure;
        assert_eq!(err.to_status().code(), Code::ResourceExhausted);
    }

    #[test]
    fn registry_passport_wrap_delegates() {
        // A wrapped PassportError should map via PassportError's rules,
        // not RegistryError's. This verifies the recursive delegation
        // in the match arm.
        let err =
            RegistryError::Passport(PassportError::AlreadyRegistered(yutha_core::AgentId::new()));
        assert_eq!(err.to_status().code(), Code::AlreadyExists);
    }

    #[test]
    fn missing_field_uses_invalid_argument() {
        let s = missing_field("passport");
        assert_eq!(s.code(), Code::InvalidArgument);
        assert!(s.message().contains("passport"));
    }
}
