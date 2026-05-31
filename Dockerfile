# === Build stage: Install system packages and dependencies ===
FROM dhi.io/node:26.2.0-debian13-dev@sha256:40b1622a9a4d9a9b2c58698ba1a5149feee1cda6d1f8207e9a168fd764601fe8 AS builder

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
FROM dhi.io/node:26.2.0-debian13@sha256:78809fed5650a9b1024983aa3695225240423f1e81180eadebba5a9633b2aeac

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
