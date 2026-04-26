FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY docker/monitored-entrypoint.sh /usr/local/bin/monitored-entrypoint

ENTRYPOINT ["monitored-entrypoint"]
