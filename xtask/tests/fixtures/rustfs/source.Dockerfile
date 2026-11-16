# Local disposable S3 functional fixture, never an application/production image.
FROM scratch AS auditable
ADD --checksum=sha256:c324af56990601354bbf40080f582ba46f8ec8b807a1388e25bb7e429d285c18 https://github.com/rust-secure-code/cargo-auditable/releases/download/v0.7.7/cargo-auditable-aarch64-unknown-linux-musl.tar.xz /arm64.tar.xz
ADD --checksum=sha256:7676443367c5e33d9fb22acef63cccb5e9202de12dae1b0579995eb3e2bc7a18 https://github.com/rust-secure-code/cargo-auditable/releases/download/v0.7.7/cargo-auditable-x86_64-unknown-linux-musl.tar.xz /amd64.tar.xz
FROM cgr.dev/chainguard/rust:latest-dev@sha256:a39f7f8d82a307b5a766253bbc6b169e806086bbabc3ed257895ae90205f0ee3 AS sources
USER 0
ARG TARGETARCH
ARG SOURCE_REVISION
ARG FIXTURE_RECIPE_SHA
LABEL org.opencontainers.image.revision=$SOURCE_REVISION org.prjxai.fixture.recipe=$FIXTURE_RECIPE_SHA
# Use the existing four public-runner CPUs, without changing runner/resources.
# Scanner quotas stay separate. Keep upstream opt3/thin LTO/defaults/GNU ABI.
ENV CARGO_HOME=/usr/local/cargo CARGO_BUILD_JOBS=4 CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
RUN ["apk", "add", "--no-cache", "cmake", "make", "pkgconf", "protoc"]
COPY --from=auditable /${TARGETARCH}.tar.xz /tmp/auditable.tar.xz
RUN ["tar", "-xJf", "/tmp/auditable.tar.xz", "--strip-components=1", "-C", "/usr/local/bin"]
WORKDIR /src
ADD --checksum=sha256:10e764074ddec7a47efea0a8ec1bb811cb73b62a0c8c26382e7dfcf30b02cb5d https://codeload.github.com/rustfs/rustfs/tar.gz/34e6449ed90e3d3a106f6655342e0b3127f33082 /tmp/source.tar.gz
RUN ["tar", "-xzf", "/tmp/source.tar.gz", "--strip-components=1", "-C", "/src"]
# One complete Cargo invocation. shadow-rs intentionally refreshes release build
# metadata between invocations; a library prebuild repeats the expensive graph.
FROM sources AS build
RUN --mount=type=cache,id=obsidian-rustfs-source-registry,target=/usr/local/cargo/registry --mount=type=cache,id=obsidian-rustfs-source-target-${FIXTURE_RECIPE_SHA},sharing=locked,target=/src/target ["cargo", "auditable", "build", "--release", "--locked", "-p", "rustfs", "--bin", "rustfs"]
RUN --mount=type=cache,id=obsidian-rustfs-source-target-${FIXTURE_RECIPE_SHA},sharing=locked,target=/src/target ["cp", "/src/target/release/rustfs", "/rustfs"]
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:a5e9991904f2034c4b39d27e3121ce7eba5a667ead9b5f3a96bfbda259be4f29 AS runtime
ARG SOURCE_REVISION
ARG FIXTURE_RECIPE_SHA
LABEL org.opencontainers.image.revision=$SOURCE_REVISION org.prjxai.fixture.recipe=$FIXTURE_RECIPE_SHA org.prjxai.fixture.upstream=34e6449ed90e3d3a106f6655342e0b3127f33082
COPY --from=build --chown=10001:10001 /rustfs /rustfs
COPY --from=build --chmod=0444 /src/LICENSE /usr/share/licenses/rustfs/LICENSE
USER 10001:10001
ENV RUSTFS_OBS_LOG_DIRECTORY=/logs RUSTFS_OBS_LOGGER_LEVEL=warn RUSTFS_OBS_ENVIRONMENT=production
ENTRYPOINT ["/rustfs"]
