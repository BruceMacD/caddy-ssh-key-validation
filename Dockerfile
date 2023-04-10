FROM caddy:builder-alpine AS builder

RUN xcaddy build \
    --with github.com/BruceMacD/caddy-ssh-key-validation

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile