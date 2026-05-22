# === Build stage: Install system packages and dependencies ===
FROM dhi.io/node:25.9.0-debian13-dev@sha256:bd8fbde408379edf34726a3b9d17b149af3cbc695733b5a0830c1cdc113c51b1 AS builder

WORKDIR /usr/src/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    netbase \
    dumb-init \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /staging/libs && \
    cp /usr/lib/*-linux-gnu/libidn2.so.* /staging/libs/ && \
    cp /usr/lib/*-linux-gnu/libunistring.so.* /staging/libs/

# Install npm dependencies
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy app code
COPY . .

# === Final stage: Minimal runtime image ===
FROM dhi.io/node:25.9.0-debian13@sha256:f37508e9a4dbf5747921d8ce6825f9f833fab373f68d73291e5d47d311be08e9

ENV NODE_ENV=production
ENV PATH=/app/node_modules/.bin:$PATH

WORKDIR /app

# Copy dumb-init
COPY --from=builder /usr/bin/dumb-init /usr/bin/dumb-init

# Copy whois binary
COPY --from=builder /usr/bin/whois /usr/bin/whois

# Copy the staged libraries to the system library path
COPY --from=builder /staging/libs/ /usr/lib/

# Copy netbase files
COPY --from=builder /etc/protocols /etc/protocols
COPY --from=builder /etc/services /etc/services

# Copy application
COPY --from=builder --chown=node:node /usr/src/app /app

EXPOSE 3000

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.js"]
