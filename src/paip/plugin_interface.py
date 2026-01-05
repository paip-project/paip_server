"""PAIP Identity Provider Plugin Interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class CertificateVerificationResult:
    """Result of verifying an agent certificate."""

    success: bool
    subject: str | None = None  # Subject from certificate (e.g., arbor:jane_doe_abc123)
    issuer: str | None = None  # IdP issuer URL
    jti: str | None = None  # Certificate JTI (for revocation checking)
    agent_public_key: str | None = None  # Agent's public key PEM
    agent_public_key_alg: str | None = None  # Algorithm for agent's key
    claims: dict[str, Any] | None = None  # Verified claims from certificate
    principal_type: str | None = None  # 'human' or 'organization'
    verified_human: bool = False  # Whether identity was verified
    crl_url: str | None = None  # URL for CRL
    ocsp_url: str | None = None  # URL for OCSP (optional)
    error: str | None = None  # Error message if success=False
    error_code: str | None = None  # Error code if success=False


@dataclass
class RevocationCheckResult:
    """Result of checking certificate revocation status."""

    is_revoked: bool
    checked_at: str | None = None
    revoked_at: str | None = None
    reason: str | None = None
    error: str | None = None  # Error during check (certificate may still be valid)


class PAIPIdentityPlugin(ABC):
    """Abstract base class for identity provider plugins.

    PAIP 2.0 uses certificate-based authentication. Plugins must implement
    certificate verification methods.

    Example:
        class MyIdPPlugin(PAIPIdentityPlugin):
            def __init__(self, jwks_url: str, crl_url: str):
                self._jwks_url = jwks_url
                self._crl_url = crl_url

            @property
            def issuer(self) -> str:
                return "https://myidp.com"

            @property
            def name(self) -> str:
                return "MyIdP"

            def get_supported_claims(self) -> list[str]:
                return ["verified_human", "full_name", "email"]

            async def get_jwks(self) -> dict[str, Any]:
                # Fetch JWKS from IdP
                ...

            async def verify_certificate(self, certificate: str) -> CertificateVerificationResult:
                # Verify certificate signature using IdP's public key
                ...

            async def check_revocation(self, jti: str, crl_url: str | None) -> RevocationCheckResult:
                # Check if certificate is revoked
                ...
    """

    @property
    @abstractmethod
    def issuer(self) -> str:
        """The IdP's issuer URL.

        This must match the 'iss' claim in certificates from this IdP.

        Returns:
            Issuer URL (e.g., 'https://arbor.id')
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the identity provider.

        Returns:
            Display name (e.g., 'Arbor ID')
        """
        pass

    @property
    def jwks_url(self) -> str:
        """URL for the IdP's JWKS endpoint.

        Returns:
            JWKS URL (e.g., 'https://arbor.id/.well-known/jwks.json')
        """
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def crl_url(self) -> str:
        """URL for the IdP's CRL endpoint.

        Returns:
            CRL URL (e.g., 'https://arbor.id/.well-known/crl.json')
        """
        return f"{self.issuer}/.well-known/crl.json"

    @abstractmethod
    def get_supported_claims(self) -> list[str]:
        """Get the list of claims this IdP can provide.

        Returns:
            List of claim names (e.g., ['verified_human', 'full_name', 'email'])
        """
        pass

    @abstractmethod
    async def get_jwks(self) -> dict[str, Any]:
        """Fetch the IdP's JSON Web Key Set.

        Returns:
            JWKS dict with 'keys' array
        """
        pass

    @abstractmethod
    async def verify_certificate(self, certificate: str) -> CertificateVerificationResult:
        """Verify an agent certificate signed by this IdP.

        This method should:
        1. Decode the JWT certificate
        2. Verify the signature using IdP's public key
        3. Check expiration
        4. Extract and return certificate data

        Note: This does NOT check revocation - use check_revocation() separately.

        Args:
            certificate: The JWT certificate from this IdP

        Returns:
            CertificateVerificationResult with certificate data
        """
        pass

    @abstractmethod
    async def check_revocation(self, jti: str, crl_url: str | None = None) -> RevocationCheckResult:
        """Check if a certificate has been revoked.

        Args:
            jti: The certificate's unique identifier
            crl_url: Optional CRL URL override (from certificate)

        Returns:
            RevocationCheckResult indicating if certificate is revoked
        """
        pass


class PluginRegistry:
    """Registry for managing IdP plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, PAIPIdentityPlugin] = {}

    def register(self, plugin: PAIPIdentityPlugin) -> None:
        """Register an IdP plugin.

        Args:
            plugin: The plugin instance to register

        Raises:
            ValueError: If a plugin with this issuer is already registered
        """
        if plugin.issuer in self._plugins:
            raise ValueError(f"Plugin already registered for issuer: {plugin.issuer}")
        self._plugins[plugin.issuer] = plugin

    def get(self, issuer: str) -> PAIPIdentityPlugin | None:
        """Get a plugin by issuer URL.

        Args:
            issuer: The IdP's issuer URL

        Returns:
            The plugin instance, or None if not found
        """
        return self._plugins.get(issuer)

    def list_issuers(self) -> list[str]:
        """Get all registered issuer URLs.

        Returns:
            List of issuer URLs
        """
        return list(self._plugins.keys())

    def list_plugins(self) -> list[PAIPIdentityPlugin]:
        """Get all registered plugins.

        Returns:
            List of plugin instances
        """
        return list(self._plugins.values())
