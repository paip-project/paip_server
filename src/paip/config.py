"""PAIP Server Configuration."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class IdentityProviderConfig(BaseModel):
    """Configuration for an identity provider."""

    id: str = Field(..., description="Unique identifier for this IdP")
    plugin: str = Field(..., description="Plugin module name")
    config: dict[str, Any] = Field(default_factory=dict, description="Plugin-specific configuration")


class ServerConfig(BaseModel):
    """Server configuration."""

    host: str = Field(default="0.0.0.0", description="Host to bind to")
    port: int = Field(default=8080, description="Port to bind to")


class KeysConfig(BaseModel):
    """Signing keys configuration."""

    private_key_path: str = Field(..., description="Path to RSA private key PEM file")
    public_key_path: str = Field(..., description="Path to RSA public key PEM file")
    key_id: str = Field(default="key-1", description="Key ID for JWKS")


class SiteConfig(BaseModel):
    """Configuration for a site this PAIP server serves."""

    audience: str = Field(..., description="The audience URL (website this token is for)")
    name: str = Field(..., description="Human-readable site name")
    trusted_providers: list[str] = Field(
        ..., description="List of IdP IDs that are trusted for this site"
    )
    required_claims: list[str] = Field(
        default_factory=lambda: ["verified_human"],
        description="Claims required for token issuance",
    )


class PAIPConfig(BaseModel):
    """Complete PAIP server configuration."""

    server: ServerConfig = Field(default_factory=ServerConfig)
    keys: KeysConfig
    identity_providers: list[IdentityProviderConfig] = Field(default_factory=list)
    sites: list[SiteConfig] = Field(default_factory=list)


class Settings(BaseSettings):
    """Environment-based settings."""

    model_config = SettingsConfigDict(env_prefix="PAIP_", env_file=".env", extra="ignore")

    config_path: str = Field(default="config/paip.yaml", description="Path to PAIP config file")
    secrets_path: str | None = Field(
        default=None, description="Path to decrypted secrets file (from SOPS)"
    )
    log_level: str = Field(default="INFO", description="Logging level")


def load_config(config_path: str, secrets_path: str | None = None) -> PAIPConfig:
    """Load PAIP configuration from YAML file.

    Args:
        config_path: Path to the main configuration file
        secrets_path: Optional path to decrypted secrets file

    Returns:
        Parsed PAIPConfig object
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(path) as f:
        config_data = yaml.safe_load(f)

    # If secrets file provided, merge it in
    if secrets_path:
        secrets_file = Path(secrets_path)
        if secrets_file.exists():
            with open(secrets_file) as f:
                secrets_data = yaml.safe_load(f)
            config_data = _deep_merge(config_data, secrets_data)

    return PAIPConfig(**config_data)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep merge two dictionaries."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
