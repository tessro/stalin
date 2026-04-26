import type ProxyPlugin from "../plugins/proxy";

const tokenUrl = "https://oauth2.googleapis.com/token";
const cacheKey = "google-workspace-access-token";
const refreshSkewMillis = 5 * 60 * 1000;

function isGoogleApiHost(host: string): boolean {
  return host === "googleapis.com" || host.endsWith(".googleapis.com");
}

function formEncode(values: Record<string, string>): string {
  return Object.entries(values)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
}

async function googleWorkspaceAccessToken(): Promise<string> {
  const cached = proxy.session.get(cacheKey);
  const cachedObject =
    cached && typeof cached === "object" && !Array.isArray(cached)
      ? (cached as { accessToken?: unknown; refreshAfter?: unknown })
      : undefined;
  if (
    cachedObject &&
    typeof cachedObject.accessToken === "string" &&
    typeof cachedObject.refreshAfter === "number" &&
    cachedObject.refreshAfter > proxy.clock.unixMillis()
  ) {
    return cachedObject.accessToken;
  }

  const clientId = await proxy.secrets.get("google_workspace_client_id");
  const clientSecret = await proxy.secrets.get("google_workspace_client_secret");
  const refreshToken = await proxy.secrets.get("google_workspace_refresh_token");
  const response = await proxy.fetch(tokenUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: formEncode({
      grant_type: "refresh_token",
      client_id: await clientId.text(),
      client_secret: await clientSecret.text(),
      refresh_token: await refreshToken.text(),
    }),
  });
  const body = await response.json();
  const tokenBody =
    body && typeof body === "object" && !Array.isArray(body)
      ? (body as { access_token?: unknown; expires_in?: unknown })
      : undefined;
  if (!response.ok) {
    throw new Error(`Google OAuth refresh failed with ${response.status}: ${JSON.stringify(body)}`);
  }
  if (!tokenBody || typeof tokenBody.access_token !== "string") {
    throw new Error("Google OAuth refresh response did not include access_token");
  }

  const expiresIn =
    typeof tokenBody.expires_in === "number" && Number.isFinite(tokenBody.expires_in)
      ? tokenBody.expires_in
      : 3600;
  proxy.session.set(cacheKey, {
    accessToken: tokenBody.access_token,
    refreshAfter: proxy.clock.unixMillis() + expiresIn * 1000 - refreshSkewMillis,
  });
  return tokenBody.access_token;
}

const plugin: ProxyPlugin = {
  async onRequestHeaders(req, ctx) {
    if (req.url.scheme !== "https" || !isGoogleApiHost(req.url.host)) {
      return { action: "continue" };
    }

    await proxy.audit.write({
      type: "auth.swap",
      message: "Replacing placeholder Google Workspace Authorization header",
      fields: {
        host: req.url.host,
        requestId: ctx.requestId,
      },
    });

    return {
      action: "continue",
      setHeaders: {
        authorization: `Bearer ${await googleWorkspaceAccessToken()}`,
      },
    };
  },
};

export default plugin;
