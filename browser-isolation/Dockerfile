# Offline, synthetic-only network isolation canary. No browser/runtime credentials.
FROM scratch
COPY --chmod=0555 bin/canary /canary
USER 65532:65532
ENTRYPOINT ["/canary"]
