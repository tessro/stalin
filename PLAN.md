# PLAN

Stalin is a MITM HTTP/2 egress proxy. It is intended to monitor and protect
egress from containers that are running AI agents, such as OpenClaw or Hermes
Agent.

It performs functions like:

- Appending or overwriting HTTP headers. Mainly this allows holding API keys
  outside agent containers and replacing placeholders at request time.
- Logging, blocking, or performing custom actions based on request shape. For
  example, backing up the existing state of an object when a modification or
  deletion is detected.

# Overview

Stalin is intended to be run in a Docker container alongside the container it
is monitoring, for example in a Docker Compose setup. It should provide a
`Dockerfile` and example `docker-compose.yml` for this. Typically the monitored
container will be on an isolated network and have `HTTP_PROXY`/`HTTPS_PROXY`
defined. The proxy container will serve as the network owner and use iptables
to limit egress to the proxy daemon only.

# Technologies

Stalin is a Rust 2024 edition project. It uses battle-tested libraries where
possible and does not attempt to implement low level functionality directly.
These libraries include:

- [Pingora](https://github.com/cloudflare/pingora) for HTTP proxying
- [v8](https://github.com/denoland/rusty_v8) for plugins

# Plugins

// =====================
// Global plugin runtime
// =====================

declare global {
  const proxy: ProxyRuntime;
  const console: Console;
}

export interface ProxyRuntime {
  readonly plugin: PluginInfo;
  readonly secrets: SecretStore;
  readonly audit: AuditLog;
  readonly crypto: CryptoApi;
  readonly clock: ClockApi;
}

export interface PluginInfo {
  readonly name: string;
  readonly version: string;
  readonly config: unknown;
}

export interface SecretStore {
  get(name: string): Promise<SecretValue>;
}

export interface SecretValue {
  readonly name: string;

  /**
   * Returns the secret as a string.
   * Host should audit that it was accessed, but never log the value.
   */
  text(): Promise<string>;

  /**
   * Convenience for Authorization: Bearer <secret>
   */
  bearer(): Promise<string>;
}

export interface AuditLog {
  write(event: AuditEvent): Promise<void>;
}

export interface AuditEvent {
  type: string;
  level?: "debug" | "info" | "warn" | "error";
  message?: string;
  fields?: Record<string, JsonValue>;
}

export interface CryptoApi {
  sha256(data: string | Uint8Array): Promise<string>;
  randomUUID(): string;
}

export interface ClockApi {
  now(): string; // ISO-8601
  unixMillis(): number;
}

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

Plugin implementation interface:

// =====================
// Plugin entrypoint
// =====================

export default interface ProxyPlugin {
  onRequestHeaders?(
    req: RequestHeadersEvent,
    ctx: HookContext,
  ): Promise<RequestHeadersResult> | RequestHeadersResult;

  onRequestBodyChunk?(
    chunk: BodyChunkEvent,
    ctx: HookContext,
  ): Promise<BodyChunkResult> | BodyChunkResult;

  onRequestBodyEnd?(
    end: BodyEndEvent,
    ctx: HookContext,
  ): Promise<BodyEndResult> | BodyEndResult;

  onResponseHeaders?(
    res: ResponseHeadersEvent,
    ctx: HookContext,
  ): Promise<ResponseHeadersResult> | ResponseHeadersResult;

  onResponseBodyChunk?(
    chunk: BodyChunkEvent,
    ctx: HookContext,
  ): Promise<BodyChunkResult> | BodyChunkResult;

  onResponseBodyEnd?(
    end: BodyEndEvent,
    ctx: HookContext,
  ): Promise<BodyEndResult> | BodyEndResult;
}

Core event types:

export interface HookContext {
  readonly requestId: string;
  readonly connectionId: string;
  readonly phase:
    | "request_headers"
    | "request_body"
    | "request_end"
    | "response_headers"
    | "response_body"
    | "response_end";

  readonly matchedRule?: string;
  readonly metadata: MetadataMap;
}

export interface MetadataMap {
  get(key: string): JsonValue | undefined;
  set(key: string, value: JsonValue): void;
  delete(key: string): void;
}

export interface RequestHeadersEvent {
  readonly id: string;
  readonly method: string;
  readonly url: UrlParts;
  readonly protocol: "http/1.1" | "h2" | "h3";
  readonly headers: HeadersView;
}

export interface ResponseHeadersEvent {
  readonly requestId: string;
  readonly status: number;
  readonly reason?: string;
  readonly headers: HeadersView;
}

export interface UrlParts {
  readonly scheme: "http" | "https";
  readonly host: string;
  readonly port?: number;
  readonly path: string;
  readonly query?: string;
  readonly full: string;
}

export interface HeadersView {
  get(name: string): string | undefined;
  getAll(name: string): string[];
  has(name: string): boolean;
  entries(): [string, string][];
}

Results should be patch-based:

export type RequestHeadersResult =
  | ContinueResult
  | DenyResult
  | RespondResult
  | RouteResult;

export type ResponseHeadersResult =
  | ContinueResult
  | RespondResult;

export interface ContinueResult {
  action: "continue";
  setHeaders?: Record<string, HeaderValue>;
  addHeaders?: Record<string, HeaderValue>;
  removeHeaders?: string[];
}

export interface RouteResult {
  action: "route";
  upstream: string;
  setHeaders?: Record<string, HeaderValue>;
  removeHeaders?: string[];
}

export interface DenyResult {
  action: "deny";
  status: number;
  body?: string;
  headers?: Record<string, HeaderValue>;
}

export interface RespondResult {
  action: "respond";
  status: number;
  body?: string | Uint8Array;
  headers?: Record<string, HeaderValue>;
}

export type HeaderValue = string | SecretValue | RedactedValue;

export interface RedactedValue {
  readonly kind: "redacted";
  readonly label: string;
  reveal(): Promise<string>;
}

Body streaming types:

export interface BodyChunkEvent {
  readonly requestId: string;
  readonly direction: "request" | "response";
  readonly index: number;
  readonly bytes: Uint8Array;
  readonly isTextLikely: boolean;
  readonly contentType?: string;
}

export type BodyChunkResult =
  | { action: "continue" }
  | { action: "replace"; bytes: Uint8Array | string }
  | { action: "drop" }
  | DenyResult
  | RespondResult;

export interface BodyEndEvent {
  readonly requestId: string;
  readonly direction: "request" | "response";
  readonly bytesSeen: number;
  readonly chunksSeen: number;
}

export type BodyEndResult =
  | { action: "continue" }
  | DenyResult
  | RespondResult;

Example plugin:

const plugin = {
  async onRequestHeaders(req, ctx) {
    if (req.url.host !== "api.openai.com") {
      return { action: "continue" };
    }

    await proxy.audit.write({
      type: "auth.swap",
      message: "Replacing placeholder Authorization header",
      fields: {
        host: req.url.host,
        requestId: ctx.requestId,
      },
    });

    return {
      action: "continue",
      setHeaders: {
        authorization: await proxy.secrets.get("openai_api_key"),
      },
      removeHeaders: ["x-placeholder-authorization"],
    };
  },

  async onRequestBodyChunk(chunk, ctx) {
    await proxy.audit.write({
      type: "payload.sample",
      fields: {
        requestId: ctx.requestId,
        direction: chunk.direction,
        bytes: chunk.bytes.length,
        sha256: await proxy.crypto.sha256(chunk.bytes),
      },
    });

    return { action: "continue" };
  },
};

export default plugin;
