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
  text(): Promise<string>;
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
  now(): string;
  unixMillis(): number;
}

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export default interface ProxyPlugin {
  onRequestHeaders?(
    req: RequestHeadersEvent,
    ctx: HookContext,
  ): Promise<RequestHeadersResult> | RequestHeadersResult;

  onRequestBodyData?(
    chunk: BodyChunkEvent,
    ctx: HookContext,
  ): Promise<BodyDataResult> | BodyDataResult;

  onRequestBodyDone?(
    body: BodyDoneEvent,
    ctx: HookContext,
  ): Promise<BodyDoneResult> | BodyDoneResult;

  onResponseHeaders?(
    res: ResponseHeadersEvent,
    ctx: HookContext,
  ): Promise<ResponseHeadersResult> | ResponseHeadersResult;

  onResponseBodyData?(
    chunk: BodyChunkEvent,
    ctx: HookContext,
  ): Promise<BodyDataResult> | BodyDataResult;

  onResponseBodyDone?(
    body: BodyDoneEvent,
    ctx: HookContext,
  ): Promise<BodyDoneResult> | BodyDoneResult;
}

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

export type RequestHeadersResult =
  | ContinueResult
  | DenyResult
  | RespondResult
  | RouteResult;

export interface ContinueResult {
  action: "continue";
  setHeaders?: Record<string, HeaderValue>;
  addHeaders?: Record<string, HeaderValue>;
  removeHeaders?: string[];
  body?: BodyPolicy;
}

export interface RouteResult {
  action: "route";
  upstream: string;
  setHeaders?: Record<string, HeaderValue>;
  removeHeaders?: string[];
  body?: BodyPolicy;
}

export interface DenyResult {
  action: "deny";
  status: number;
  body?: string | Uint8Array;
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

export type BodyPolicy =
  | { mode?: "stream" }
  | { mode: "buffer"; maxBytes: number; overflow?: "deny" | "stream" };

export interface BodyChunkEvent {
  readonly requestId: string;
  readonly direction: "request" | "response";
  readonly index: number;
  readonly bytes: Uint8Array;
  readonly contentType?: string;
}

export interface BodyDoneEvent {
  readonly requestId: string;
  readonly direction: "request" | "response";
  readonly bytesSeen: number;
  readonly chunksSeen: number;
  readonly bytes?: Uint8Array;
  readonly text?: string;
  readonly contentType?: string;
}

export type BodyDataResult = { action: "continue" };

export type BodyDoneResult =
  | { action: "continue" }
  | { action: "replace"; body: string | Uint8Array }
  | DenyResult
  | RespondResult;

export type ResponseHeadersResult =
  | {
      action: "continue";
      setHeaders?: Record<string, HeaderValue>;
      addHeaders?: Record<string, HeaderValue>;
      removeHeaders?: string[];
      body?: BodyPolicy;
    }
  | RespondResult;
