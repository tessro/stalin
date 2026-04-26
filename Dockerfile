FROM rust:1.92-bookworm AS build
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iptables nodejs npm \
    && npm install -g esbuild \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/stalin /usr/local/bin/stalin
COPY examples/stalin-mitm.toml /etc/stalin/config.toml
COPY examples/openai-auth.plugin.ts /etc/stalin/openai-auth.plugin.ts
ENV STALIN_CONFIG=/etc/stalin/config.toml
EXPOSE 8080
ENTRYPOINT ["stalin"]
