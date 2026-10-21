# syntax=docker/dockerfile:1.7
FROM rust:1.99.1-alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS build
RUN apk add --no-cache musl-dev cmake make perl clang lld binutils
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
# Alpine's host target is musl. Fail if the resulting executable has an interpreter.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked && \
    ! readelf -l target/release/obsidian-sync-server | grep -q INTERP && \
    cp target/release/obsidian-sync-server /server

# Explicit test target; never inherited by the final runtime image.
FROM build AS tests
COPY tests ./tests
COPY examples ./examples
COPY config ./config
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --locked && cargo fmt --all -- --check && \
    cargo clippy --workspace --all-targets --locked -- -D warnings && \
    cargo test --workspace --locked

# Chainguard's static image is distroless (no shell/package manager), with current CA roots.
FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
COPY --from=build --chown=65532:65532 /server /server
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/server"]
CMD ["serve"]
