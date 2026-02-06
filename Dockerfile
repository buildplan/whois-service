# === Build stage: Install system packages and dependencies ===
FROM dhi.io/node:25-dev AS builder

WORKDIR /usr/src/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    netbase \
    dumb-init \
    && rm -rf /var/lib/apt/lists/*

# Install npm dependencies
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy app code
COPY . .


# === Final stage: Minimal runtime image ===
FROM dhi.io/node:25

ENV NODE_ENV=production
ENV PATH=/app/node_modules/.bin:$PATH

WORKDIR /app

# Copy dumb-init
COPY --from=builder /usr/bin/dumb-init /usr/bin/dumb-init

# Copy whois binary
COPY --from=builder /usr/bin/whois /usr/bin/whois

# Copy shared libraries
COPY --from=builder /usr/lib/x86_64-linux-gnu/libidn2.so.0 /usr/lib/x86_64-linux-gnu/libidn2.so.0
COPY --from=builder /usr/lib/x86_64-linux-gnu/libunistring.so.5 /usr/lib/x86_64-linux-gnu/libunistring.so.5

# Copy netbase files
COPY --from=builder /etc/protocols /etc/protocols
COPY --from=builder /etc/services /etc/services

# Copy application
COPY --from=builder --chown=node:node /usr/src/app /app

EXPOSE 3000

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.js"]
