FROM caddy:builder AS builder

RUN xcaddy build \
    --with github.com/BruceMacD/caddy-ssh-key-validation

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 8000