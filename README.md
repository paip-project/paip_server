# PAIP Server

**Reference implementation of the Personal Agent Identification Protocol (PAIP)** - A certificate-based framework for verifying that AI agents represent authenticated, real humans when interacting with web APIs.

## The Problem

As AI agents become capable of booking appointments, making purchases, and accessing services on behalf of users, websites face a critical question: **how do they know an agent represents a real person?**

PAIP solves this using a model inspired by TLS/SSL certificates - Identity Providers act as Certificate Authorities, issuing credentials that prove an agent belongs to a verified human.

## Protocol Specification

**[Read the full PAIP Protocol Specification →](PROTOCOL.md)**

The protocol specification covers:
- Certificate format and lifecycle (90-day validity)
- Identity Provider requirements (JWKS, CRL, OCSP)
- Handshake flow with cryptographic proof-of-possession
- Session token format
- Security considerations

## How It Works

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        PAIP Certificate-Based Flow                       │
└──────────────────────────────────────────────────────────────────────────┘

1. ONE-TIME SETUP (User verifies identity with IdP)
   ┌────────┐                          ┌─────────────────┐
   │  User  │ ──── Verify identity ───>│ Identity        │
   │        │      (docs + liveness)   │ Provider (IdP)  │
   │        │                          │                 │
   │ Agent  │ ──── Register agent ────>│ Issues 90-day   │
   │        │      public key          │ certificate     │
   └────────┘                          └─────────────────┘

2. HANDSHAKE (Agent proves it holds valid certificate)
   ┌────────┐                          ┌─────────────────┐
   │ Agent  │ ──── Certificate + ─────>│   PAIP Server   │
   │        │      Signature           │                 │
   │        │                          │ • Verify cert   │
   │        │ <─── Session token ──────│ • Check CRL     │
   │        │      (1 hour)            │ • Verify sig    │
   └────────┘                          └─────────────────┘

3. API ACCESS (Agent uses session token)
   ┌────────┐                          ┌─────────────────┐
   │ Agent  │ ──── API request + ─────>│    Website      │
   │        │      session token       │    Backend      │
   │        │                          │                 │
   │        │ <─── Response ───────────│ Verifies token  │
   └────────┘                          └─────────────────┘
```

### Key Security Properties

| Attack | Protection |
|--------|------------|
| Certificate theft | Useless without agent's private key |
| Session token theft | Limited to 1 hour, single website |
| Replay attacks | Timestamp + nonce in handshake |
| Compromised certificate | Instant revocation via CRL/OCSP |

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose (optional)

### Local Development

```bash
# Clone and setup
git clone https://github.com/your-org/paip-server.git
cd paip-server
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Generate signing keys
python -m paip.main generate-keys

# Run server
python -m paip.main serve --reload
```

### Test the Handshake

```bash
# Health check
curl http://localhost:8080/health

# See test_handshake.py for full certificate-based flow example
```

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/.well-known/jwks.json` | PAIP server's public keys |
| `POST` | `/handshake` | Exchange certificate for session token |
| `POST` | `/verify` | Verify a session token |

### Handshake Request (v2.0)

```json
{
  "certificate": "<agent certificate JWT from IdP>",
  "audience": "https://example-clinic.com",
  "timestamp": "2025-01-04T15:30:00Z",
  "nonce": "random-unique-string",
  "signature": "<agent signs {audience}|{timestamp}|{nonce}>"
}
```

### Handshake Response

```json
{
  "success": true,
  "session_token": "<PAIP session token>",
  "expires_at": "2025-01-04T16:30:00Z",
  "claims": {
    "verified_human": true,
    "full_name": "Jane Doe"
  }
}
```

## Configuration

### Main Configuration (`config/paip.yaml`)

```yaml
server:
  host: "0.0.0.0"
  port: 8080

keys:
  private_key_path: "keys/private.pem"
  public_key_path: "keys/public.pem"
  key_id: "key-1"

identity_providers:
  - id: mock
    plugin: mock
    config: {}

sites:
  - audience: "https://example-clinic.com"
    name: "Example Clinic"
    trusted_providers:
      - mock
    required_claims:
      - verified_human
```

## Creating IdP Plugins

To add support for a new identity provider, implement the `PAIPIdentityPlugin` interface:

```python
from paip.plugin_interface import (
    PAIPIdentityPlugin,
    CertificateVerificationResult,
    RevocationCheckResult,
)

class MyIdPPlugin(PAIPIdentityPlugin):
    @property
    def issuer(self) -> str:
        return "https://myidp.com"

    @property
    def name(self) -> str:
        return "MyIdP"

    def get_supported_claims(self) -> list[str]:
        return ["verified_human", "full_name", "email"]

    async def get_jwks(self) -> dict:
        # Fetch IdP's public keys
        ...

    async def verify_certificate(self, certificate: str) -> CertificateVerificationResult:
        # Verify certificate signature using IdP's public key
        # Check expiration
        # Extract agent public key and claims
        ...

    async def check_revocation(self, jti: str, crl_url: str | None) -> RevocationCheckResult:
        # Check if certificate is on the CRL
        ...
```

## Project Structure

```
paip_server/
├── PROTOCOL.md              # Protocol specification
├── README.md
├── src/paip/
│   ├── server.py            # FastAPI application
│   ├── models.py            # Request/response models
│   ├── tokens.py            # JWT + signature utilities
│   ├── plugin_interface.py  # IdP plugin interface
│   └── plugins/
│       └── mock.py          # Mock IdP for testing
├── config/
│   └── paip.yaml            # Server configuration
└── keys/                    # Signing keys (gitignored)
```

## Related Projects

- **[Arbor ID](../arbor_id)** - A PAIP-compatible Identity Provider that verifies humans via document + liveness checks

## License

MIT License - see LICENSE file for details.
