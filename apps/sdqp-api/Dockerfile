FROM rust:1-slim-bookworm AS builder

WORKDIR /workspace

COPY Cargo.toml Cargo.lock rust-toolchain.toml clippy.toml deny.toml ./
COPY apps ./apps
COPY crates ./crates
COPY configs ./configs
COPY db ./db
COPY proto ./proto

RUN cargo build --release -p sdqp-api

FROM apache/hive:4.0.0 AS hive-client

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl default-jre-headless procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /workspace/target/release/sdqp-api /usr/local/bin/sdqp-api
COPY --from=builder /workspace/configs /app/configs
COPY --from=hive-client /opt/hive /opt/hive
COPY --from=hive-client /opt/hadoop /opt/hadoop

ENV RUST_LOG=info \
    HIVE_HOME=/opt/hive \
    HADOOP_HOME=/opt/hadoop \
    PATH=/opt/hive/bin:/opt/hadoop/bin:${PATH} \
    SDQP_CONFIG_ROOT=/app/configs \
    SDQP_ENVIRONMENT=local-docker \
    SDQP_API_HOST=0.0.0.0 \
    SDQP_API_PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=12 CMD curl --fail --silent http://127.0.0.1:8080/readyz > /dev/null || exit 1

ENTRYPOINT ["sdqp-api"]
