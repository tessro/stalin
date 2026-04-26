# TODO

## Core Proxy

- Extend MITM TLS beyond the current CONNECT path:
  - expose CA generation/export workflow for local development
  - add integration tests with a client that trusts the configured CA
- Make HTTP/2 proxying first-class for both client-facing and upstream traffic,
  including plugin hook coverage on h2 requests.
- Decide how to handle HTTP/3. Pingora 0.8 in this repo does not expose a QUIC
  or HTTP/3 listener API.
- Add WebSocket frame inspection on the Pingora path. HTTP/1.1 upgrade
  proxying is in place; inspection still needs frame parsing and plugin hooks.
- Add container egress enforcement:
  - entrypoint script or supervisor for iptables setup
  - rules that limit monitored-container egress to the proxy daemon
  - Docker Compose isolated network example
- Add integration tests that exercise the proxy with real HTTP clients and
  upstream test servers.

## Plugin Runtime

- Extend response header hooks with integration coverage through the proxy
  forwarding path.
- Extend request body hooks:
  - support binary replacement bodies
  - add integration coverage through the proxy forwarding path
  - decide whether stream-mode hook failures should fail open or fail closed
- Extend response body hooks:
  - support binary replacement bodies
  - add integration coverage through the proxy forwarding path
  - decide whether stream-mode hook failures should fail open or fail closed
- Implement body hook actions:
  - `continue`
  - `replace`
  - `drop`
  - `deny`
  - `respond`
- Add `HookContext.metadata` with per-request state shared across hook phases.
- Populate `HookContext.matchedRule` where plugin execution is tied to a rule.
- Expand `plugins/proxy.d.ts` to cover the full plugin interface from
  `PLAN.md`.

## Plugin Results

- Implement synthetic `respond` as distinct from `deny`.
- Implement `RedactedValue` and `reveal()`.
- Decide whether `RouteResult.addHeaders` is a supported extension or should be
  removed to match `PLAN.md`.
- Add tests for route behavior, including path/query preservation and explicit
  upstream paths.

## Secrets And Audit

- Avoid materializing all configured secrets into V8 on every plugin call.
- Make `proxy.secrets.get()`, `SecretValue.text()`, and `SecretValue.bearer()`
  true host-backed async operations.
- Preserve arbitrary audit `fields` in the host audit log.
- Ensure secret access is audited without logging secret values.
- Add redaction tests for logs and error paths.

## V8 And Esbuild

- Cache esbuild bundle output instead of bundling every plugin at startup.
- Cache compiled plugin state or isolates where safe.
- Add plugin execution limits:
  - timeout
  - memory limit
  - maximum bundle size
  - maximum audit event count per hook
- Improve plugin compile/load errors with plugin name, path, and source
  location where available.
- Add tests for skipped plugins when `esbuild` is missing or bundling fails.
- Add examples for plain JavaScript and TypeScript plugin authoring.

## Configuration

- Document the complete `config.toml` schema.
- Add validation for duplicate rule/plugin names.
- Add validation for invalid header names and unreachable plugin paths.
- Add configurable plugin behavior on load failure:
  - warn and skip
  - fail startup
- Add config examples for common AI API providers.

## Packaging

- Ensure the runtime image includes or documents `esbuild`.
- Add a production entrypoint that initializes networking before starting
  Stalin.
- Add healthcheck endpoint or command.
- Add release build instructions.
