# Use BuildKit's built-in Dockerfile frontend; no remote custom frontend is needed.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:833c48f1faf32c90e6f9501a2410a9aa28ceb2c594102edd4470053c30efa089 AS build
USER 0
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup ZIG_GLOBAL_CACHE_DIR=/build/zig-cache
RUN ["apk", "add", "--no-cache", "rustup=1.29.3-r1", "build-base", "zig=0.17.1-r1", "cmake", "git"]
RUN ["rustup", "toolchain", "install", "1.99.1", "--profile", "minimal", "--component", "clippy", "--component", "rustfmt"]
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY xtask ./xtask
# GNU SDK, native static-musl output; preserve undefined-behavior and ARM erratum checks.
RUN ["rustup", "run", "1.99.1", "rustc", "--edition=2024", "-Dwarnings", "xtask/src/native_musl.rs", "-o", "/usr/local/bin/native-musl-cargo"]
RUN ["rustup", "run", "1.99.1", "rustc", "--edition=2024", "--test", "-Dwarnings", "xtask/src/native_musl.rs", "-o", "/tmp/native-musl-tests"]
RUN ["/tmp/native-musl-tests"]
RUN ["ln", "-s", "/usr/local/bin/native-musl-cargo", "/usr/local/bin/native-musl-cc"]
RUN ["ln", "-s", "/usr/local/bin/native-musl-cargo", "/usr/local/bin/native-musl-cxx"]
RUN ["ln", "-s", "/usr/local/bin/native-musl-cargo", "/usr/local/bin/native-musl-info"]
RUN ["ln", "-s", "/usr/local/bin/native-musl-cargo", "/usr/local/bin/native-musl-install-target"]
RUN ["native-musl-install-target"]
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=obsidian-sync-native-musl-target-v2,target=/build/target \
    --mount=type=cache,target=/build/zig-cache \
    native-musl-cargo build --release --locked -p obsidian-sync-server && \
    readelf -l target/*-unknown-linux-musl/release/obsidian-sync-server > /tmp/server-program-headers && \
    ! grep -q INTERP /tmp/server-program-headers && \
    cp target/*-unknown-linux-musl/release/obsidian-sync-server /server

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
    --mount=type=cache,id=obsidian-sync-native-musl-target-v2,target=/build/target \
    --mount=type=cache,target=/build/zig-cache \
    native-musl-cargo build --locked && native-musl-cargo fmt --all -- --check && \
    native-musl-cargo clippy --workspace --all-targets --locked -- -D warnings && \
    native-musl-cargo test --workspace --locked

# Distroless static/nonroot runtime: only the verified musl executable is added.
FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
COPY --from=build --chown=65532:65532 /server /server
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/server"]
CMD ["serve"]
