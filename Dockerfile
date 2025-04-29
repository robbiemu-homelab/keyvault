FROM rust:1.86.0-bookworm AS builder

# Install build dependencies first!
RUN apt-get update && apt-get install -y libssl-dev pkg-config ca-certificates

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "// dummy" > src/lib.rs
RUN cargo fetch

COPY . ./
RUN cargo build --release

# --- Final runtime image ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/keyvault ./
COPY queries.yaml ./

CMD ["./keyvault"]
