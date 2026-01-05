# PAIP Server

**Personal Agent Identification Protocol (PAIP) Server** - An open-source framework for verifying that automated agents represent authenticated, real humans when interacting with web APIs.

## Overview

PAIP enables websites to become "agent-ready" by providing a standardized way to:

1. **Discover** - Agents learn what identity verification a website requires
2. **Handshake** - Agents exchange identity provider tokens for PAIP session tokens
3. **Verify** - Websites verify that API requests come from verified humans

See [PROTOCOL.md](PROTOCOL.md) for the full protocol specification.

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose (for containerized deployment)
- [SOPS](https://github.com/getsops/sops) (for secrets management)
- [age](https://github.com/FiloSottile/age) (for encryption)

### Local Development Setup

1. **Clone and create virtual environment:**

```bash
git clone https://github.com/your-org/paip-server.git
cd paip-server

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

2. **Generate signing keys:**

```bash
python -m paip.main generate-keys
```

This creates `keys/private.pem` and `keys/public.pem`.

3. **Run the server:**

```bash
python -m paip.main serve --reload
```

The server will start at `http://localhost:8080`.

4. **Test the health endpoint:**

```bash
curl http://localhost:8080/health
```

### Docker Deployment

1. **Generate keys (if not already done):**

```bash
mkdir -p keys
python -m paip.main generate-keys
```

2. **Start with Docker Compose:**

```bash
docker compose up -d
```

For development with hot reload:

```bash
docker compose --profile dev up paip-server-dev
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
  - id: healthverify
    plugin: healthverify
    config:
      verification_endpoint: "https://api.healthverify.com/verify"
      # API key loaded from secrets

sites:
  - audience: "https://drsmith-derm.com"
    name: "Dr. Smith's Dermatology"
    trusted_providers:
      - healthverify
    required_claims:
      - verified_human
      - full_name
```

### Secrets Management with SOPS

PAIP uses [SOPS](https://github.com/getsops/sops) to manage sensitive configuration like API keys.

#### Initial Setup with age

1. **Install age and SOPS:**

```bash
# macOS
brew install age sops

# Linux
# Download from https://github.com/FiloSottile/age/releases
# Download from https://github.com/getsops/sops/releases
```

2. **Generate an age key:**

```bash
age-keygen -o ~/.config/sops/age/keys.txt
```

3. **Get your public key:**

```bash
age-keygen -y ~/.config/sops/age/keys.txt
# Output: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

4. **Update `.sops.yaml` with your public key:**

```yaml
creation_rules:
  - path_regex: config/secrets\.yaml$
    age: >-
      age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

5. **Create and encrypt secrets:**

```bash
# Create secrets file from example
cp config/secrets.example.yaml config/secrets.yaml

# Edit with your real values
nano config/secrets.yaml

# Encrypt in place
sops -e -i config/secrets.yaml
```

6. **To edit encrypted secrets:**

```bash
sops config/secrets.yaml
```

7. **For Docker deployment, decrypt to a separate file:**

```bash
sops -d config/secrets.yaml > config/secrets.decrypted.yaml
```

Then set `PAIP_SECRETS_PATH=config/secrets.decrypted.yaml` in your environment.

## API Reference

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/.well-known/jwks.json` | Public keys for token verification |
| `POST` | `/handshake` | Exchange IdP token for session token |
| `POST` | `/verify` | Verify a session token |

### Handshake

```bash
curl -X POST http://localhost:8080/handshake \
  -H "Content-Type: application/json" \
  -d '{
    "idp": "https://mock.paip.local",
    "idp_token": "any-token-for-mock",
    "audience": "https://example-clinic.com"
  }'
```

### Verify Token

```bash
curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<session-token-from-handshake>"
  }'
```

## Creating IdP Plugins

To add support for a new identity provider, create a plugin in `src/paip/plugins/`:

```python
# src/paip/plugins/myidp.py

from paip.plugin_interface import PAIPIdentityPlugin, VerificationResult
import httpx

class MyIdPPlugin(PAIPIdentityPlugin):
    def __init__(self, api_key: str, endpoint: str):
        self._api_key = api_key
        self._endpoint = endpoint

    @property
    def issuer(self) -> str:
        return "https://myidp.com"

    @property
    def name(self) -> str:
        return "MyIdP"

    def get_supported_claims(self) -> list[str]:
        return ["verified_human", "full_name", "email"]

    async def verify_token(self, token: str) -> VerificationResult:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._endpoint,
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={"token": token}
            )

            if response.status_code != 200:
                return VerificationResult(
                    success=False,
                    error="Verification failed"
                )

            data = response.json()
            return VerificationResult(
                success=True,
                subject=data["user_id"],
                claims={
                    "verified_human": data["verified"],
                    "full_name": data["name"],
                    "email": data["email"]
                }
            )

def create_plugin(config: dict) -> MyIdPPlugin:
    return MyIdPPlugin(
        api_key=config["api_key"],
        endpoint=config["verification_endpoint"]
    )
```

Then add to your configuration:

```yaml
identity_providers:
  - id: myidp
    plugin: myidp
    config:
      verification_endpoint: "https://api.myidp.com/verify"
      api_key: "${MYIDP_API_KEY}"  # From secrets
```

## Development

### Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=paip --cov-report=html
```

### Linting and Type Checking

```bash
ruff check src tests
ruff format src tests
mypy src
```

## Project Structure

```
paip_server/
├── src/paip/
│   ├── __init__.py
│   ├── main.py           # CLI entry point
│   ├── server.py         # FastAPI application
│   ├── config.py         # Configuration loading
│   ├── models.py         # Pydantic models
│   ├── tokens.py         # JWT handling
│   ├── plugin_interface.py  # IdP plugin ABC
│   └── plugins/
│       ├── __init__.py
│       └── mock.py       # Mock IdP for testing
├── config/
│   ├── paip.yaml         # Main configuration
│   └── secrets.example.yaml
├── tests/
├── keys/                 # Generated signing keys (gitignored)
├── PROTOCOL.md          # Protocol specification
├── Dockerfile
├── docker-compose.yaml
├── pyproject.toml
└── README.md
```

## License

MIT License - see LICENSE file for details.
