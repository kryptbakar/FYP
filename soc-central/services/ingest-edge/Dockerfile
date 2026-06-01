# ingest-edge — Go build. Build context is the REPO ROOT so we can bake in the
# single-source telemetry schema (see docker-compose: context: ., dockerfile: ...).
FROM golang:1.23-alpine AS build
WORKDIR /src

# Copy the service source and the shared schema (for go:embed).
COPY services/ingest-edge/ ./
COPY schema/telemetry/v1/envelope.schema.json ./schema/envelope.schema.json

# Resolve deps (writes go.sum) and build a static binary.
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -o /out/ingest-edge .

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache wget ca-certificates && adduser -D -u 10001 appuser
COPY --from=build /out/ingest-edge /usr/local/bin/ingest-edge
USER appuser
EXPOSE 8443 8081
# Healthcheck hits the plain-HTTP health port (no client cert required).
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8081/health || exit 1
ENTRYPOINT ["/usr/local/bin/ingest-edge"]
