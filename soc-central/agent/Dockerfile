# SOC Central endpoint agent. Build context is the repo root for consistency
# with the other services (see docker-compose: context: ., dockerfile: agent/Dockerfile).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY agent/ ./
# Zero external deps -> a fully offline, static build.
RUN CGO_ENABLED=0 go build -trimpath -o /out/agent .

# --- runtime: Debian so we can install the official osquery package ---
FROM debian:bookworm-slim
ARG INSTALL_OSQUERY=true
ARG OSQUERY_VERSION=5.12.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates \
 && if [ "$INSTALL_OSQUERY" = "true" ]; then \
      ( wget -qO /tmp/osquery.deb "https://pkg.osquery.io/deb/osquery_${OSQUERY_VERSION}-1.linux_amd64.deb" \
        && apt-get install -y --no-install-recommends /tmp/osquery.deb \
        && rm -f /tmp/osquery.deb ) \
      || echo "WARN: osquery install failed; agent will run without the osquery collector" ; \
    fi \
 && rm -rf /var/lib/apt/lists/*

# Writable directory the FIM demo can touch to generate events.
RUN mkdir -p /watch

COPY --from=build /out/agent /usr/local/bin/agent
ENTRYPOINT ["/usr/local/bin/agent"]
