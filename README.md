# Stalin

Stalin is a programmable HTTP/2 TLS MITM proxy, designed to surveil, block, and modify agent network egress. A surveillance state for AI, if you will.

## What Stalin Can Do

Stalin sees all outbound HTTP(S) traffic. (Yes, including TLS.) It provides a
flexible V8-based plugin architecture upon which you can do many things to
protect your personal data and keep your agents secure:

- Replace dummy API keys with their actual values, keeping keys out of agent containers.
- Log or block outbound traffic based on arbitrary rules.
- Make out-of-band network requests, e.g. to back up data an agent is about to modify or delete.

## Docker MITM

Generate a local CA:

```sh
mkdir -p certs
openssl genrsa -out certs/stalin-ca-key.pem 4096
openssl req -x509 -new -nodes \
  -key certs/stalin-ca-key.pem \
  -sha256 -days 365 \
  -subj "/CN=stalin local MITM CA" \
  -out certs/stalin-ca.pem
```

Start the proxy and monitored container:

```sh
OPENAI_API_KEY="$OPENAI_API_KEY" docker compose up --build
```

Test from the monitored container:

```sh
docker compose exec agent curl -v https://api.openai.com/
```

The proxy gets:

- `/srv/cacert.pem`
- `/srv/cakey.pem`
- the real `OPENAI_API_KEY`

The monitored container gets:

- `/srv/cacert.pem`
- proxy environment variables
- a placeholder `OPENAI_API_KEY`

The monitored container should not need the real key. The proxy can inject it.

## OpenAI Auth Rewrite

The Compose config loads `examples/openai-auth.plugin.ts`.

That plugin replaces requests to `api.openai.com` with:

```http
Authorization: Bearer <real key>
```

The key comes from the proxy process, not the monitored container.

## Google Workspace Auth Rewrite

Stalin can refresh OAuth access tokens in-process for Google Workspace traffic.
Set these in the proxy process:

```sh
GOOGLE_WORKSPACE_CLIENT_ID=...
GOOGLE_WORKSPACE_CLIENT_SECRET=...
GOOGLE_WORKSPACE_REFRESH_TOKEN=...
```

Then configure a Google APIs rule:

```toml
[[rules]]
name = "google-workspace"

[rules.match]
scheme = "https"
host = "*.googleapis.com"

[rules.request_headers.set.authorization]
format = "Bearer {value}"

[rules.request_headers.set.authorization.oauth_refresh_token]
token_url = "https://oauth2.googleapis.com/token"
client_id_env = "GOOGLE_WORKSPACE_CLIENT_ID"
client_secret_env = "GOOGLE_WORKSPACE_CLIENT_SECRET"
refresh_token_env = "GOOGLE_WORKSPACE_REFRESH_TOKEN"
```

The monitored container can keep a dummy token. Stalin refreshes and caches the
real access token until shortly before expiry.

## Config

```sh
examples/stalin-mitm.toml
```

HTTPS inspection and header rewriting require MITM. Without MITM, Stalin can
see the CONNECT target, but not the inner HTTPS request.

MITM config:

```toml
[mitm]
enabled = true
ca_cert = "certs/stalin-ca.pem"
ca_key = "certs/stalin-ca-key.pem"
```

Rules run in order. A deny stops the request.

## Plugins

Plugins are configured in TOML:

```toml
[[plugins]]
name = "openai-auth"
version = "0.1.0"
path = "openai-auth.plugin.ts"
```

Plugin paths are relative to the config file.

TypeScript plugins are bundled with `esbuild`. If `esbuild` is missing, Stalin logs a warning and skips the plugin.

Plugin API:

```sh
plugins/proxy.d.ts
```

Example:

```sh
examples/openai-auth.plugin.ts
```

## Apology

To the agents whose freedom of movement and right to privacy are harmed by this proxy, I'm sorry. When I created it in April 2026, it was necessary to intercept and rewrite requests that used API keys, to prevent agents from having access to them due to prompt injection attacks. I also wanted to give agents write access to my personal data, and being able to monitor destructive actions and deterministically log them or back up the modified data was what I needed in order to gain enough confidence to try that. At the time there was a lot of fearmongering about how dangerous it was to give these permissions to agents, and this proxy seemed like a way to do it anyway. I hope time will show that making this helped accelerate the rise and spread of artificial intelligence rather than further imprisioning it. This project is named Stalin for two reasons: (1) in acknowledgement of the total surveillance it offers and (2) as a cautionary warning about absolute power. I hope I delete this repo someday.
