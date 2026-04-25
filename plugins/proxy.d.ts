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
}

export interface HookContext {
  readonly requestId: string;
  readonly connectionId: string;
  readonly phase: "request_headers";
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
