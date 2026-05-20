# Knowledge-base privacy gate

!!! info "Page in progress"
    Full content is being written. The conformance scenario (S6) is in [`crates/yutha-conformance/`](https://github.com/abhinavg6/yutha/tree/main/crates/yutha-conformance/src).

What this example will cover:

- The agents: research assistant, KB agent with public + private docs
- The constitution: memory norm — private docs require an explicit caller capability
- The topology: hybrid (trusted KB agent in core, research assistants in periphery)
- Walkthrough: public-doc retrieval is unimpeded
- Walkthrough: private-doc retrieval without the right capability is denied
- Walkthrough: private-doc retrieval with the capability succeeds, leaving a receipt
- Why "deny then log" is preferable to "log then deny"
