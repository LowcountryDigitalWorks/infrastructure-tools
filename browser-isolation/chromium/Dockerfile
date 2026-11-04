# Pinned, official Playwright test image; Microsoft Artifact Registry index digest.
# This is restricted to trusted synthetic fixtures, NEVER real untrusted sites.
# Base browsers included; matching JS Playwright package installed at build time.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f
WORKDIR /opt/ldw-browser-proof
RUN npm install --no-save --ignore-scripts --no-audit --no-fund --omit=dev playwright@1.64.1 \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin ldwprobe
COPY --chmod=0444 probe.js kernel_attestation.js /opt/ldw-browser-proof/
USER 10001:10001
ENV HOME=/tmp
ENTRYPOINT ["node", "/opt/ldw-browser-proof/probe.js"]
