# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
FROM rust:1.99.1-alpine3.24@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87 AS build
RUN apk add --no-cache musl-dev cmake make perl clang lld binutils git
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY xtask ./xtask
# Alpine's host target is musl. Fail if the resulting executable has an interpreter.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p obsidian-sync-server && \
    ! readelf -l target/release/obsidian-sync-server | grep -q INTERP && \
    cp target/release/obsidian-sync-server /server

# Explicit test target; never inherited by the final runtime image.
FROM build AS tests
COPY tests ./tests
COPY examples ./examples
COPY config ./config
COPY scripts ./scripts
COPY .github ./.github
COPY .cargo ./.cargo
COPY Dockerfile .gitignore docker-compose*.yml ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --locked && cargo fmt --all -- --check && \
    cargo clippy --workspace --all-targets --locked -- -D warnings && \
    cargo test --workspace --locked

# Chainguard's static image is distroless (no shell/package manager), with current CA roots.
FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
COPY --from=build --chown=65532:65532 /server /server
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/server"]
CMD ["serve"]
