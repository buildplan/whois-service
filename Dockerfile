# === Build stage: Install system packages and dependencies ===
FROM dhi.io/node:25-dev AS builder

WORKDIR /usr/src/app

# Install system dependencies (whois, netbase) and dumb-init
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

# Copy dumb-init from builder
COPY --from=builder /usr/bin/dumb-init /usr/bin/dumb-init

# Copy whois and netbase binaries
COPY --from=builder /usr/bin/whois /usr/bin/whois
COPY --from=builder /usr/bin/getent /usr/bin/getent

# Copy necessary shared libraries for whois (if needed)
COPY --from=builder /lib/x86_64-linux-gnu/libidn2.so.0 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libunistring.so.2 /lib/x86_64-linux-gnu/

# Copy netbase data files
COPY --from=builder /etc/protocols /etc/protocols
COPY --from=builder /etc/services /etc/services

# Copy application with dependencies from builder
COPY --from=builder --chown=node:node /usr/src/app /app

WORKDIR /app

# Expose port
EXPOSE 3000

# Start with dumb-init
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.js"]
