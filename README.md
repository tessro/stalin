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

## Docker MITM Trial

Generate a local CA for the proxy. The private key stays mounted only in the
proxy container; the monitored container receives only the public CA
certificate.

```sh
mkdir -p certs
openssl genrsa -out certs/stalin-ca-key.pem 4096
openssl req -x509 -new -nodes \
  -key certs/stalin-ca-key.pem \
  -sha256 -days 365 \
  -subj "/CN=stalin local MITM CA" \
  -out certs/stalin-ca.pem
```

Start the proxy and monitored test container:

```sh
docker compose up --build
```

Then test from the monitored container:

```sh
docker compose exec agent curl https://api.openai.com/
```

The proxy container sees the CA material at `/srv/cacert.pem` and
`/srv/cakey.pem`, plus the real `OPENAI_API_KEY` from the host environment. The
monitored `agent` container sees only `/srv/cacert.pem` and a harmless
placeholder `OPENAI_API_KEY`; its entrypoint installs the CA certificate into
Debian's system trust store and sets common CA bundle environment variables for
runtimes that do not use the system defaults.

The compose MITM config loads `examples/openai-auth.plugin.ts`. That plugin runs
inside the proxy and replaces requests to `api.openai.com` with
`Authorization: Bearer <real key>` before forwarding upstream.

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
