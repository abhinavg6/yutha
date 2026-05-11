//! [`Performative`] — speech-act-theoretic message kinds.
//!
//! Eleven variants at v1.0; new performatives require an RFC and a
//! minor-version bump. Unknown performatives MUST be surfaced
//! ([`crate::EnvelopeError::UnknownPerformative`]) rather than silently
//! coerced.

/// The set of speech-act kinds an envelope can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Performative {
    // Negotiation primitives.
    /// "I propose action X under terms T."
    Propose,
    /// "I counter with terms T'."
    Counter,
    /// "I commit to terms T."
    Commit,
    /// "I abort this exchange."
    Abort,
    /// "I release a resource I held."
    Release,
    // Information primitives.
    /// "What is the current state of X?"
    Query,
    /// "X is now Y."
    Inform,
    /// "An error occurred; details inside payload."
    Error,
    // Coordination primitives.
    /// "Please perform X."
    RequestAction,
    /// "I confirm X happened."
    Confirm,
    /// "I decline to perform X."
    Decline,
}

impl Performative {
    /// Parse from the proto wire-tag integer.
    pub fn from_wire(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::Propose),
            2 => Some(Self::Counter),
            3 => Some(Self::Commit),
            4 => Some(Self::Abort),
            5 => Some(Self::Release),
            6 => Some(Self::Query),
            7 => Some(Self::Inform),
            8 => Some(Self::Error),
            9 => Some(Self::RequestAction),
            10 => Some(Self::Confirm),
            11 => Some(Self::Decline),
            _ => None,
        }
    }

    /// Return the proto wire-tag integer.
    pub const fn to_wire(self) -> i32 {
        match self {
            Self::Propose => 1,
            Self::Counter => 2,
            Self::Commit => 3,
            Self::Abort => 4,
            Self::Release => 5,
            Self::Query => 6,
            Self::Inform => 7,
            Self::Error => 8,
            Self::RequestAction => 9,
            Self::Confirm => 10,
            Self::Decline => 11,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trip_all_variants() {
        for p in [
            Performative::Propose,
            Performative::Counter,
            Performative::Commit,
            Performative::Abort,
            Performative::Release,
            Performative::Query,
            Performative::Inform,
            Performative::Error,
            Performative::RequestAction,
            Performative::Confirm,
            Performative::Decline,
        ] {
            assert_eq!(Performative::from_wire(p.to_wire()), Some(p));
        }
    }

    #[test]
    fn unknown_wire_value_returns_none() {
        assert!(Performative::from_wire(0).is_none());
        assert!(Performative::from_wire(99).is_none());
    }
}
