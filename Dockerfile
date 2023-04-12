FROM caddy:builder AS builder

# Add an ARG for cache busting
ARG CACHEBUST=1

# Copy the local 'agent' directory to the '/tmp/agent' directory
COPY agent /tmp/agent

# Build the project with the local copy of the agent
RUN xcaddy build \
    --with github.com/BruceMacD/caddy-ssh-key-validation=/tmp/agent

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY agent/Caddyfile /etc/caddy/Caddyfile

EXPOSE 8000
