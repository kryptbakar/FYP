# SOC Central analyst console — dependency-free static SPA on nginx.
# No build step, no npm, no CDN: every asset is in this image, so it runs fully
# air-gapped (see docs/DECISIONS.md D-044). nginx also reverse-proxies /api -> FastAPI.
FROM nginx:1.27-alpine

# unprivileged-friendly listen port 8080 (see nginx.conf)
COPY web/console/nginx.conf /etc/nginx/conf.d/default.conf
RUN rm -f /etc/nginx/conf.d/default.conf.bak 2>/dev/null || true

COPY web/console/index.html /usr/share/nginx/html/index.html
COPY web/console/assets/    /usr/share/nginx/html/assets/

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=4s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/ >/dev/null 2>&1 || exit 1
