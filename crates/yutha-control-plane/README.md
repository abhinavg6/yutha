# yutha-control-plane

The Yutha control-plane binary. Wires together the in-memory backends from `yutha-receipt`, `yutha-passport`, `yutha-capability`, `yutha-transport`, and `yutha-registry` into a runnable skeleton.

## What's here

- **`yutha` binary**: starts a tokio runtime, constructs the in-memory backends, wires the resolver adapter from passport to receipt, builds a closed-mode topology + registry, logs the bring-up at INFO, then awaits Ctrl-C.

## What's NOT here

- A real network listener — the transport skeleton uses `MemoryTransport`; a NATS adapter lands when transport gets its production impl.
- Config file parsing — the topology is hard-coded for the skeleton. A YAML / TOML config parser is the next step.
- Constitution engine integration — Phase 2.
- Enforcement loop — Phase 2.

## Running

```bash
cargo run -p yutha-control-plane
```

You should see structured log output showing the swarm bring-up and the bring-up of each component. Hit Ctrl-C to exit.

## Layering

```
yutha-control-plane
├── yutha-registry          (admission)
│   └── yutha-passport      (identity)
├── yutha-capability        (authority)
├── yutha-transport         (envelopes)
└── yutha-receipt           (audit)
    └── via PassportResolverAdapter → yutha-passport
```
