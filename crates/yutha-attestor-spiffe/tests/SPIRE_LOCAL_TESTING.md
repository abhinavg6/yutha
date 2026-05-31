# Running the SPIFFE Attestor integration test locally

The integration test at [`tests/integration.rs`](./integration.rs) is
`#[ignore]`-gated and skips by default. To exercise the full Workload-API
verify path against a real SPIRE agent — JWT-SVID minted by SPIRE, verified
by [`SpiffeAttestor`](../src/attestor.rs) — you need a running SPIRE
server + agent and two env vars set.

This doc is the recipe that works on macOS (Apple Silicon) end-to-end. The
broad shape (config files + three terminals + env vars) also works on
Linux; the only platform-specific bit is the SPIRE binaries themselves.

The non-integration tests ([`tests/forged_jwts.rs`](./forged_jwts.rs)) cover
the verify path with in-tree ES256 keypairs and bundle files — they're a
faster default and don't need any of this. Pick this up only when you want
the "real SPIRE round trip" smoke.

> **CI:** The integration test is meant to run in GitHub Actions on
> `ubuntu-latest` (where SPIRE ships a native `linux-amd64-musl` tarball);
> the macOS recipe below is for local developer use. See E10 (Phase E
> verification gate) for the CI wiring once it lands.

---

## 1. Install SPIRE

SPIRE 1.15.1 ships pre-built tarballs only for `linux-{amd64,arm64}` and
`windows-amd64`. **No darwin binaries.** macOS users build from source;
Linux users grab the tarball.

### macOS (build from source)

Requires Go 1.22+. `brew install go` if you don't have it.

```bash
mkdir -p /tmp/spire-test && cd /tmp/spire-test
git clone --branch v1.15.1 --depth 1 https://github.com/spiffe/spire.git src

cd src
# CGO must be enabled — SPIRE's sqlite3 datastore links against the C
# sqlite library. `CGO_ENABLED=0` builds will fail at startup with
# "sqlite3 is not a supported dialect when CGO is not enabled".
go build -o /tmp/spire-test/spire-server ./cmd/spire-server
go build -o /tmp/spire-test/spire-agent  ./cmd/spire-agent
cd /tmp/spire-test

# First-time C-toolchain users will get an Xcode Command Line Tools
# prompt the first time `go build` invokes clang. Accept it (~1.5 GB).

export PATH="$PWD:$PATH"
spire-server --version   # → 1.15.1-dev-unk
spire-agent --version
```

### Linux (download tarball)

```bash
VERSION=1.15.1
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
mkdir -p /tmp/spire-test && cd /tmp/spire-test

curl -L -o spire.tar.gz \
  "https://github.com/spiffe/spire/releases/download/v${VERSION}/spire-${VERSION}-linux-${ARCH}-musl.tar.gz"
tar xzf spire.tar.gz
export PATH="/tmp/spire-test/spire-${VERSION}/bin:$PATH"

spire-server --version
spire-agent --version
```

---

## 2. Config files

Drop both into `/tmp/spire-test/`.

### `server.conf`

```hcl
server {
  bind_address = "127.0.0.1"
  bind_port = "8081"
  trust_domain = "example.org"
  data_dir = "/tmp/spire-test/server-data"
  log_level = "DEBUG"
  ca_ttl = "168h"
  default_x509_svid_ttl = "1h"
  default_jwt_svid_ttl = "5m"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/tmp/spire-test/server-data/datastore.sqlite3"
    }
  }
  NodeAttestor "join_token" {
    plugin_data {}
  }
  KeyManager "memory" {
    plugin_data = {}
  }
}
```

### `agent.conf`

```hcl
agent {
  data_dir = "/tmp/spire-test/agent-data"
  log_level = "DEBUG"
  trust_domain = "example.org"
  server_address = "127.0.0.1"
  server_port = "8081"
  socket_path = "/tmp/spire-test/agent.sock"
  trust_bundle_path = "/tmp/spire-test/agent-data/bootstrap.crt"
}

plugins {
  NodeAttestor "join_token" {
    plugin_data {}
  }
  KeyManager "memory" {
    plugin_data = {}
  }
  WorkloadAttestor "unix" {
    plugin_data {}
  }
}
```

```bash
mkdir -p /tmp/spire-test/{server-data,agent-data}
```

---

## 3. Run SPIRE (three terminals)

### Terminal 1 — server

```bash
spire-server run -config /tmp/spire-test/server.conf
```

Leave this running. SPIRE creates `/tmp/spire-server/private/api.sock` for
the admin client.

### Terminal 2 — bootstrap + agent

```bash
# 1) Bootstrap the agent's trust bundle from the server.
spire-server bundle show \
  -socketPath /tmp/spire-server/private/api.sock \
  > /tmp/spire-test/agent-data/bootstrap.crt

# 2) Generate a join token. (Burned after the agent uses it.)
JOIN_TOKEN=$(spire-server token generate \
  -spiffeID spiffe://example.org/agent \
  -socketPath /tmp/spire-server/private/api.sock \
  -ttl 600 | awk '{print $2}')

# 3) Create a registration entry that matches the current shell's uid
#    (the cargo-test process inherits it). NOTE: the SPIRE CLI does
#    NOT accept a generic `-ttl`; use `-jwtSVIDTTL` if you want an
#    explicit one, or omit and use the server.conf default.
spire-server entry create \
  -socketPath /tmp/spire-server/private/api.sock \
  -spiffeID spiffe://example.org/test-workload \
  -parentID spiffe://example.org/agent \
  -selector unix:uid:$(id -u)

# 4) Start the agent with the join token.
spire-agent run -config /tmp/spire-test/agent.conf -joinToken "$JOIN_TOKEN"
```

Leave this running too. SPIRE creates `/tmp/spire-test/agent.sock` for the
Workload API.

### Terminal 3 — cargo test

```bash
cd /Users/abhinavgarg/Documents/Claude/Yutha

YUTHA_ATTESTOR_SPIFFE_INTEGRATION_SOCKET=/tmp/spire-test/agent.sock \
YUTHA_ATTESTOR_SPIFFE_INTEGRATION_AUDIENCE=yutha-test-audience \
cargo test -p yutha-attestor-spiffe --test integration -- --ignored --nocapture
```

Expected output:

```
running 2 tests
test workload_api_source_rejects_wrong_audience ... ok
test workload_api_source_verifies_workload_api_svid ... ok
integration roundtrip OK — attested external_identity = spiffe://example.org/test-workload
```

---

## 4. Teardown

```bash
# Stop the two SPIRE processes (Ctrl-C in terminals 1 and 2).
rm -rf /tmp/spire-test /tmp/spire-server /tmp/spire-src
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `sqlite3 is not a supported dialect when CGO is not enabled` | Built with `CGO_ENABLED=0` | Rebuild without that env var; install Xcode CLT if clang missing |
| `flag provided but not defined: -ttl` on `entry create` | Generic `-ttl` was removed | Use `-jwtSVIDTTL N` (or omit; server.conf has a default) |
| Test fails with `connection refused` to `agent.sock` | Agent not yet attested / socket not yet created | Wait ~2 s after agent startup; check `ls /tmp/spire-test/agent.sock` |
| Test fails with `audience mismatch` on the happy-path case | Audience env var doesn't match what the SPIRE client minted for | Confirm `YUTHA_ATTESTOR_SPIFFE_INTEGRATION_AUDIENCE` matches what `cargo test` requested — the test code passes its env-var value as the SVID audience, so any value works as long as it's consistent |
| `entry create` complains about `selector type "unix" not found` | Agent doesn't have the `unix` workload attestor plugin enabled | Make sure `agent.conf` has the `WorkloadAttestor "unix" { plugin_data {} }` block from §2 |

---

## What this test exercises that the forged-JWT tests don't

The forged-JWT suite in [`tests/forged_jwts.rs`](./forged_jwts.rs) covers
the verify path end-to-end with `jsonwebtoken`-signed JWTs and an in-tree
JWKS bundle file. The integration test adds, on top of that:

1. **`JwtSource` (Workload-API streaming source) actually drives the
   `BundleSource` trait** — confirms our `BundleCache::WorkloadApi` impl
   correctly delegates `bundle_for_trust_domain` to the SDK's cached
   bundle set.
2. **An SDK-built SVID round-trips through our verify path** — confirms
   we're not relying on any jsonwebtoken-specific quirks the SPIRE
   signature path doesn't share.

Neither is strictly load-bearing for the Yutha-side contract — both
are essentially smoke tests of the `spiffe` crate's plumbing — which is
why the forged-JWT suite is the primary verification of the verify
path and the integration test is `#[ignore]`-gated.
