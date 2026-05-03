# Multi-arch image built by goreleaser dockers_v2 (linux/amd64, linux/arm64).
# Per-arch binaries are staged at <TARGETPLATFORM>/lighthouse in the
# build context; buildx populates ${TARGETPLATFORM} per platform target.
#
# Configuration: provide either
#   - LIGHTHOUSE_TOKEN env var (simplest for k8s/docker-compose), or
#   - a YAML config mounted at /etc/lighthouse/lighthouse.yaml
# Both can be combined; LIGHTHOUSE_TOKEN takes precedence over the YAML token.
FROM alpine:3.20

ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S lighthouse \
    && adduser -S -G lighthouse -u 10001 -h /etc/lighthouse lighthouse \
    && mkdir -p /var/lib/lighthouse /etc/lighthouse \
    && chown -R lighthouse:lighthouse /var/lib/lighthouse /etc/lighthouse

COPY ${TARGETPLATFORM}/lighthouse /usr/local/bin/lighthouse

USER lighthouse:lighthouse
WORKDIR /etc/lighthouse

ENTRYPOINT ["/usr/local/bin/lighthouse"]
