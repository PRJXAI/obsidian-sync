# Experimental service fixture only; not the server image or an adopted CI dependency.
FROM rustfs/rustfs:1.0.4@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2 AS supplier
FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
COPY --from=supplier --chown=65532:65532 /usr/bin/rustfs /rustfs
USER 65532:65532
ENV RUSTFS_OBS_LOG_DIRECTORY=/logs RUSTFS_OBS_LOGGER_LEVEL=warn RUSTFS_OBS_ENVIRONMENT=production
ENTRYPOINT ["/rustfs"]
