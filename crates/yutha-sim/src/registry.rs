//! [`PersonaRegistry`] — string-discriminator → persona constructor.
//!
//! The YAML scenario format (3e-G) and the CLI subcommand (3e-H)
//! both surface persona instances by a string discriminator (e.g.
//! `"refund_attacker"`). The registry maps each discriminator to a
//! constructor that materialises a `Box<dyn Persona>` from the
//! persona's per-instance config blob.
//!
//! 3e-B / 3e-C ship the registry surface with no built-in
//! personas. 3e-D, 3e-E, 3e-F each add one canonical persona's
//! `register(&mut PersonaRegistry)` call to the standard
//! `with_canonical_personas()` constructor. Operators implementing
//! custom personas register them by name themselves before
//! handing the registry to the harness.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use yutha_core::AgentId;

use crate::error::{Result, SimError};
use crate::persona::Persona;

/// A constructor for one persona impl.
///
/// Signature is intentionally simple — `(name, agent_id, config) →
/// boxed persona`. The harness owns agent_id assignment and name
/// formatting; the constructor's job is just to deserialise its
/// config and stand up its internal state.
pub type PersonaConstructor =
    Arc<dyn Fn(String, AgentId, Value) -> Result<Box<dyn Persona>> + Send + Sync>;

/// Maps persona discriminators to constructor closures.
#[derive(Clone, Default)]
pub struct PersonaRegistry {
    entries: HashMap<String, PersonaConstructor>,
}

impl std::fmt::Debug for PersonaRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&String> = self.entries.keys().collect();
        f.debug_struct("PersonaRegistry")
            .field("registered", &names)
            .finish()
    }
}

impl PersonaRegistry {
    /// Empty registry. Equivalent to
    /// [`PersonaRegistry::default()`]. Operators use this when
    /// registering only their own custom personas.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a constructor under `name`. Overwrites any prior
    /// entry for the same name — last-write-wins.
    pub fn register<F>(&mut self, name: impl Into<String>, constructor: F)
    where
        F: Fn(String, AgentId, Value) -> Result<Box<dyn Persona>> + Send + Sync + 'static,
    {
        self.entries.insert(name.into(), Arc::new(constructor));
    }

    /// `true` when the registry knows the discriminator.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Names of registered personas, sorted. Useful for surfacing
    /// helpful error messages when the user mistypes a discriminator.
    pub fn registered_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        names
    }

    /// Construct a persona given its discriminator + assigned
    /// agent_id + config blob. Returns [`SimError::UnknownPersona`]
    /// when the discriminator isn't registered.
    pub fn build(
        &self,
        discriminator: &str,
        instance_name: String,
        agent_id: AgentId,
        config: Value,
    ) -> Result<Box<dyn Persona>> {
        let constructor = self
            .entries
            .get(discriminator)
            .ok_or_else(|| SimError::UnknownPersona(discriminator.to_string()))?;
        constructor(instance_name, agent_id, config)
    }
}
