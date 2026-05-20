# Python SDK

!!! info "Page in progress"
    Full content is being written. The package README at [`sdks/python/README.md`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/README.md) is the canonical surface reference today.

Topics this page will cover:

- Installation (`uv add yutha`)
- The `YuthaClient` surface: admission, envelope, receipts, capability, constitution
- Async / await model and connection lifecycle
- Bearer auth and token refresh
- Sending an envelope; subscribing to a stream
- Capability minting, delegation, revocation from the client
- Error model: `ConstitutionDenied`, `CapabilityDenied`, `Unauthenticated`
- Logging and OpenTelemetry hooks
