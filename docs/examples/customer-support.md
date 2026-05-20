# Customer support with a refund cap

!!! info "Page in progress"
    Full content is being written. The runnable demo is at [`sdks/python/examples/s1_support_queue.py`](https://github.com/abhinavg6/yutha/blob/main/sdks/python/examples/s1_support_queue.py). The conformance scenario (S5) lives in [`crates/yutha-conformance/src/s5_refund_cap.rs`](https://github.com/abhinavg6/yutha/tree/main/crates/yutha-conformance/src).

What this example will cover:

- The agents: classifier, L1 support, L2 escalation
- The constitution: refund cap, escalation procedure, evict-on-bypass policy
- The topology: closed (operator-vetted agents only)
- Step-by-step walkthrough of a refund happy-path
- A bypass attempt and how it's caught + evicted
- Audit trail: every consequential receipt with annotations
