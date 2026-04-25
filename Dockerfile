FROM rust:1.92-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/stalin /usr/local/bin/stalin
COPY examples/stalin.yml /etc/stalin/stalin.yml
ENV STALIN_CONFIG=/etc/stalin/stalin.yml
EXPOSE 8080
ENTRYPOINT ["stalin"]
