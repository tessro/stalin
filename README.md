# Stalin

Stalin is a Rust egress proxy for agent containers. It keeps credentials and
egress policy outside the monitored container, rewrites outbound HTTP headers,
audits requests, and can block traffic by request shape.

This repository currently contains the first working implementation:

- Pingora-owned downstream and upstream proxy path with HTTP/1.1 and HTTP/2
  session handling.
- Explicit HTTP proxying for absolute-form `HTTP_PROXY` requests.
- HTTPS `CONNECT` tunneling with host-level allow, deny, and audit decisions.
- Optional HTTP/1.1 and HTTP/2 MITM TLS interception for CONNECT requests when
  configured with a trusted local CA.
- HTTP/1.1 upgrade tunneling for WebSocket-style proxy traffic.
- Rule-driven request header mutation.
- V8 request-header plugins with secret, audit, crypto, and clock host APIs.
- Secret-backed header values from environment variables.
- JSONL audit logging.
- Docker and Compose examples for sidecar deployment.

Deep body inspection and streaming body hooks described in `PLAN.md` are
intentionally isolated as follow-on work.

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
encrypted tunnels unless `[mitm]` is enabled and the monitored client trusts the
configured CA certificate.

```toml
[mitm]
enabled = true
ca_cert = "certs/stalin-ca.pem"
ca_key = "certs/stalin-ca-key.pem"
```

MITM mode advertises `h2` and `http/1.1` to the client side of the intercepted
TLS session. Upstream requests still use TLS and Pingora's upstream HTTP/2
preference.

## V8 Plugins

Request-header plugins are configured in TOML:

```toml
[[plugins]]
name = "openai-auth"
version = "0.1.0"
path = "openai-auth.plugin.ts"
```

Plugin paths are resolved relative to the config file. Stalin uses `esbuild`
from `PATH` to bundle TypeScript/JavaScript plugins before loading them into
V8. If `esbuild` is unavailable or bundling fails, Stalin logs a warning and
skips that plugin.

See [examples/openai-auth.plugin.ts](examples/openai-auth.plugin.ts) and
[plugins/proxy.d.ts](plugins/proxy.d.ts).
