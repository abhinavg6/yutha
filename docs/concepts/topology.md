# Topology

!!! info "Page in progress"
    Full content is being written. The canonical reference until then is [`/spec/topology/`](../reference/specs.md).

Three topologies are first-class:

- **Closed.** Operator-vetted agents only. Highest trust, narrowest participation. Default for production swarms.
- **Open.** Public participation gated by sybil-resistance and reputation. Used for crowd-sourced workflows.
- **Hybrid.** Trusted core (closed) plus open periphery. The core can grant attenuated capabilities to periphery agents; periphery agents can earn promotion via sustained good behavior.

Topology is chosen at swarm activation and is part of the operator's policy surface, not a deployment detail.
