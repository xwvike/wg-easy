FROM docker.io/library/node:22-bookworm-slim AS build_node_modules

# Copy Web UI
COPY src /app
WORKDIR /app
RUN npm ci --omit=dev &&\
    mv node_modules /node_modules

# Copy build result to a new image.
# This saves a lot of disk space.
FROM docker.io/library/node:22-bookworm-slim
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ip -o link show up dev wg0 | grep -q 'wg0:'
COPY --from=build_node_modules /app /app

# Move node_modules one directory up, so during development
# we don't have to mount it in a volume.
# This results in much faster reloading!
#
# Also, some node_modules might be native, and
# the architecture & OS of your development machine might differ
# than what runs inside of docker.
COPY --from=build_node_modules /node_modules /node_modules

# Copy the needed wg-password scripts
COPY --from=build_node_modules /app/wgpw.sh /bin/wgpw
RUN chmod +x /bin/wgpw

# Install Linux packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    dumb-init \
    iproute2 \
    iptables \
    wireguard-tools && \
    rm -rf /var/lib/apt/lists/*

# Run Web UI
WORKDIR /app
CMD ["/usr/bin/dumb-init", "node", "server.js"]
