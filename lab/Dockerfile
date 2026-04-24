# ── Stage 1: Build yaler binaries ─────────────────────────────────────────────
FROM debian:bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential cmake perl xz-utils \
    clang libclang-dev pkg-config ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

# Go toolchain — required by BoringSSL's cmake build system
RUN curl -fsSL https://go.dev/dl/go1.21.13.linux-amd64.tar.gz \
    | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:$PATH"

# Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:$PATH"

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin yaler-server --bin yaler-client

# ── Stage 2: Minimal runtime ───────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/yaler-server /usr/local/bin/
COPY --from=builder /src/target/release/yaler-client /usr/local/bin/
