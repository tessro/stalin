import type ProxyPlugin from "../plugins/proxy";

const plugin: ProxyPlugin = {
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
        authorization: (await proxy.secrets.get("openai_api_key")).bearer(),
      },
      removeHeaders: ["x-placeholder-authorization"],
    };
  },
};

export default plugin;
