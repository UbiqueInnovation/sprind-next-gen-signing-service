FROM rust:1.81.0-alpine AS builder
RUN apk add --no-cache musl-dev

WORKDIR /app

# Setup project strucutre
RUN mkdir -p /app/next-gen-signatures/src /app/next-gen-signing-service/src

# Cache dependencies
COPY ./Cargo.toml /app/Cargo.toml
COPY ./Cargo.lock /app/Cargo.lock
COPY ./next-gen-signatures/Cargo.toml /app/next-gen-signatures/Cargo.toml
COPY ./next-gen-signing-service/Cargo.toml /app/next-gen-signing-service/Cargo.toml
RUN touch /app/next-gen-signatures/src/lib.rs /app/next-gen-signing-service/src/main.rs

# NOTE: This build will fail, but it will download the dependencies and cache the step.
RUN cargo build --release || true

# Build project
COPY ./next-gen-signatures /app/next-gen-signatures
COPY ./next-gen-signing-service /app/next-gen-signing-service

# NOTE: Somehow cargo sometimes fails to realize that the source code was updated, this fixed it.
RUN touch /app/next-gen-signatures/src/lib.rs /app/next-gen-signing-service/src/main.rs

RUN cargo build --release



FROM alpine as runtime

WORKDIR /app

COPY --from=builder /app/target/release/next-gen-signing-service /usr/bin/web-server
# NOTE: Config is loaded dynamically at startup so we can add it after building.
COPY ./Rocket.toml /app/Rocket.toml

CMD ["/usr/bin/web-server"]
