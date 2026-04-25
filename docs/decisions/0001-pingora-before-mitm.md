# Decision: Move To Pingora Before MITM

## Status

Accepted and implemented for HTTP/1.1 and HTTP/2. HTTP/3 is excluded for now
because Pingora 0.8 in this repo does not expose a QUIC or HTTP/3 listener API.

## Context

Stalin needs to inspect and control agent egress across:

- HTTP/1.1 requests
- HTTP/2 requests
- WebSocket upgrades and frames
- HTTPS traffic after explicit MITM termination
- request and response body streams

The implementation used Axum/Hyper as the downstream server and reqwest as the
upstream client. That was useful for getting policy and V8 plugin hooks working
quickly, but it was not the substrate described in `PLAN.md` and it would fight
the next features:

- MITM needs TLS termination, dynamic certificates, ALPN, and HTTP/2 handling at
  the proxy boundary.
- WebSocket inspection needs upgrade handling and frame-level control, not just
  HTTP request/response buffering.
- Body hooks need streaming both directions.
- Pingora already has protocol/session abstractions for HTTP/1, HTTP/2, TLS,
  listeners, services, and body filters.

## Decision

Do the Pingora migration before MITM.

The core proxy should use Pingora downstream sessions and Pingora upstream
connectors. MITM should be built on top of that boundary, not on top of the old
Axum/reqwest implementation.

## Sequencing

1. Introduce a Pingora HTTP service that owns downstream HTTP/1.1 and h2c
   sessions. Done.
2. Move existing request-header policy and V8 `onRequestHeaders` execution into
   the Pingora request-header path. Done.
3. Replace reqwest upstream forwarding with Pingora upstream connectors. Done.
4. Add WebSocket upgrade detection and tunnel/frame plumbing in the Pingora path.
5. Add request/response streaming body hooks.
6. Add MITM TLS termination and dynamic certificate handling.
7. Remove Axum/reqwest once parity is reached. Done.

## Consequences

- Short term: the proxy core migration is larger than adding isolated MITM code
  to the current implementation.
- Long term: MITM, WebSockets, HTTP/2, and streaming hooks share one protocol
  stack instead of accumulating adapters around Axum/reqwest.
- Existing policy, config, secrets, audit, and V8 plugin code should remain
  reusable; the migration target is the transport/proxy layer.
