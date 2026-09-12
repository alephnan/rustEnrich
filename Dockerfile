FROM rust:1.98.1-bookworm AS build
WORKDIR /build
COPY . .
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /data \
    && chown 10001:10001 /data \
    && chmod 0700 /data
COPY --from=build /build/target/release/rustenrich /usr/local/bin/rustenrich
COPY LICENSE /usr/share/licenses/rustenrich/LICENSE
ENV ENRICH_BIND_ADDR=0.0.0.0:8080 \
    ENRICH_DATABASE_PATH=/data/rustenrich.sqlite
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --output /dev/null http://127.0.0.1:8080/health/ready || exit 1
ENTRYPOINT ["/usr/local/bin/rustenrich"]
