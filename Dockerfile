FROM caddy:builder AS builder

# Add an ARG for cache busting
ARG CACHEBUST=1

# clone the repo to force the build not to cache earlier versions
RUN apk add --no-cache git
RUN git clone https://github.com/BruceMacD/caddy-ssh-key-validation.git /tmp/caddy-ssh-key-validation
RUN xcaddy build \
    --with github.com/BruceMacD/caddy-ssh-key-validation=/tmp/caddy-ssh-key-validation

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 8000