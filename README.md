# WiredAlter WHOIS Service

A robust, tiered WHOIS intelligence API and web service. It provides deep registration data (Registrar, Expiry, Nameservers) combined with real-time DNS resolution.

## Features

* **Tier-3 Architecture:** Intelligently switches between `linux-whois` binary, IANA Deep Discovery (recursive referral lookup), and NPM libraries to find data where other tools fail.
* **Ultimate Safety Net:** If a Registry is offline (e.g., `whois.nic.google`), it gracefully falls back to IANA data instead of crashing.
* **Dual Data:** Returns both **WHOIS Registration** details AND **Resolved IP (DNS)** records in a single query.
* **Smart Parsing:** Handle difficult formats like Japanese (`.jp`) bracketed nameservers and strict European GDPR outputs.
* **Privacy First:** Runs entirely in-memory. Zero logging of user queries.
* **Dockerized:** Secure, non-root container deployment with `docker compose`.

## Usage

### Web Interface
Visit the homepage, [whois.wiredalter.com](https://whois.wiredalter.com) to search for any domain name manually.

### CLI / API Access

Developers can use standard tools to fetch data over HTTPS.

#### 1. Text Report (CLI Friendly)

By default, `curl` requests receive a clean, human-readable report.

```bash
curl https://whois.wiredalter.com/google.com
```

**Sample Output:**

```text
🔎 WHOIS Report: google.com
------------------------------------------------
IPv4: 142.250.187.206
IPv6: 2a00:1450:4009:81e::200e
------------------------------------------------
Domain Name: google.com
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registrar: MarkMonitor Inc.
Creation Date: 1997-09-15T04:00:00Z
Registry Expiry Date: 2028-09-14T04:00:00Z
...
```

#### 2. Full JSON Data (API)

If you need structured data for scripts, use the API endpoint. This returns parsed fields (Registrar, Expiry) alongside the raw output.

```bash
curl https://whois.wiredalter.com/api/lookup/google.com
```

**Example JSON Response:**

```json
{
  "query": "google.com",
  "type": "domain",
  "method": "Linux Binary",
  "timestamp": "2025-12-24T12:00:00.000Z",
  "parsed": {
    "registrar": "MarkMonitor Inc.",
    "created": "1997-09-15T04:00:00Z",
    "expires": "2028-09-14T04:00:00Z",
    "nameservers": [
      "ns1.google.com",
      "ns2.google.com"
    ]
  },
  "ips": {
    "v4": ["142.250.187.206"],
    "v6": ["2a00:1450:4009:81e::200e"]
  },
  "raw": "Domain Name: google.com..."
}
```

## Installation (Self-Hosted)

1. **Clone the repository:**

```bash
git clone https://github.com/buildplan/whois-service.git
cd whois-service
```

2. **Run with Docker:**

**Option 1: Quick Start**: Default Docker compose file in the repo uses pre-built image from GitHub registry `ghcr.io/buildplan/whois-service:latest`.

```bash
docker compose up -d
```

**Option 2: Build from Source**: To build the image locally (recommended for customization), edit `docker-compose.yml` to use `build: .`.

1. **Customize the UI (Optional):** You can edit `views/index.html` to change branding, colors, or layout.
2. **Edit `docker-compose.yml`:**

```yaml
services:
  whois-service:
    # Build locally from source
    build: .
    image: whois-service:local
    container_name: whois-service
    restart: unless-stopped
    
    # Run as secure non-root user
    user: "node"
    
    # Security hardening
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

    # Map Port 3001 locally
    ports:
      - "127.0.0.1:3001:3001"

    environment:
      - NODE_ENV=production
      - PORT=3001

    deploy:
      resources:
        limits:
          cpus: '0.25'
          memory: 128M
```

Then build and run:

```bash
docker compose up -d --build
```

## License

This project is licensed under the **MIT License**.
