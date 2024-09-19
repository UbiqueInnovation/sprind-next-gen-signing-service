FROM rust:1.81.0-alpine AS builder
RUN apk add --no-cache musl-dev

WORKDIR /app

# Setup project strucutre
RUN mkdir -p /app/next-gen-signatures/src /app/next-gen-signing-service/src

COPY ./Cargo.toml /app/Cargo.toml
COPY ./Cargo.lock /app/Cargo.lock
COPY ./next-gen-signatures /app/next-gen-signatures
COPY ./next-gen-signing-service /app/next-gen-signing-service

RUN cargo build --release



FROM alpine AS runtime

WORKDIR /app

COPY --from=builder /app/target/release/next-gen-signing-service /usr/bin/web-server
# NOTE: Config is loaded dynamically at startup so we can add it after building.
COPY ./Rocket.toml /app/Rocket.toml

CMD ["/usr/bin/web-server"]
