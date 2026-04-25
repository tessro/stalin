# Stalin

Stalin is a Rust egress proxy for agent containers. It keeps credentials and
egress policy outside the monitored container, rewrites outbound HTTP headers,
audits requests, and can block traffic by request shape.

This repository currently contains the first working implementation:

- Explicit HTTP proxying for absolute-form `HTTP_PROXY` requests.
- HTTPS `CONNECT` tunneling with host-level allow, deny, and audit decisions.
- Rule-driven request header mutation.
- Secret-backed header values from environment variables.
- JSONL audit logging.
- Docker and Compose examples for sidecar deployment.

Deep TLS MITM body inspection and the V8 JavaScript plugin host described in
`PLAN.md` are intentionally isolated as follow-on work. The policy model and
TypeScript declarations are laid out so those hooks can be wired in without
reworking proxy request handling.

## Run

```sh
cargo run -- --config examples/stalin.toml
```

Then point a client at the proxy:

```sh
HTTP_PROXY=http://127.0.0.1:8080 curl http://example.com/
HTTPS_PROXY=http://127.0.0.1:8080 curl https://example.com/
```

## Configuration

See [examples/stalin.toml](examples/stalin.toml).

Rules are evaluated in order. A matching `deny` stops the request. Header
patches apply only to inspectable HTTP requests; `CONNECT` requests are
encrypted tunnels, so Stalin can audit or block the target authority but cannot
rewrite inner HTTPS headers without a future MITM mode.
