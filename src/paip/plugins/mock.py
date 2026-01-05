"""Mock Identity Provider Plugin for Testing.

This plugin is for development and testing purposes only.
It accepts mock certificates and returns mock verification results.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from paip.plugin_interface import (
    PAIPIdentityPlugin,
    CertificateVerificationResult,
    RevocationCheckResult,
)


class MockIdentityPlugin(PAIPIdentityPlugin):
    """Mock identity provider for testing.

    WARNING: This plugin should NEVER be used in production.
    It generates its own signing keys and accepts mock certificates.
    """

    def __init__(
        self,
        mock_claims: dict[str, Any] | None = None,
        revoked_certificates: list[str] | None = None,
    ):
        """Initialize the mock plugin.

        Args:
            mock_claims: Optional claims to include in mock certificates.
            revoked_certificates: List of JTIs to consider revoked.
        """
        self._mock_claims = mock_claims or {
            "full_name": "Test User",
            "email": "test@example.com",
        }
        self._revoked_certificates = set(revoked_certificates or [])

        # Generate mock signing keys
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()

    @property
    def issuer(self) -> str:
        return "https://mock.paip.local"

    @property
    def name(self) -> str:
        return "Mock IdP (Testing Only)"

    def get_supported_claims(self) -> list[str]:
        return ["verified_human", "full_name", "email"]

    async def get_jwks(self) -> dict[str, Any]:
        """Get mock JWKS."""
        import base64

        public_numbers = self._public_key.public_numbers()

        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, byteorder="big"
        )
        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, byteorder="big"
        )

        n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")
        e_b64 = base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode("ascii")

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "mock-key-1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": n_b64,
                    "e": e_b64,
                }
            ]
        }

    async def verify_certificate(self, certificate: str) -> CertificateVerificationResult:
        """Verify a mock certificate.

        For testing, this accepts any certificate from the mock issuer.
        WARNING: This does NOT verify signatures - for testing only!

        Args:
            certificate: The JWT certificate

        Returns:
            CertificateVerificationResult
        """
        try:
            # For the mock plugin, we accept any certificate from our issuer
            # without signature verification (this is testing only!)
            payload = jwt.decode(
                certificate,
                options={"verify_signature": False},
            )

            # Verify issuer matches
            if payload.get("iss") != self.issuer:
                return CertificateVerificationResult(
                    success=False,
                    error=f"Invalid issuer: expected {self.issuer}",
                    error_code="invalid_issuer",
                )

            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp, tz=UTC) < datetime.now(UTC):
                return CertificateVerificationResult(
                    success=False,
                    error="Certificate has expired",
                    error_code="certificate_expired",
                )

            # Extract certificate data
            paip_cert = payload.get("paip_cert", {})
            agent = paip_cert.get("agent", {})
            principal = paip_cert.get("principal", {})
            claims = paip_cert.get("claims", self._mock_claims.copy())
            revocation = paip_cert.get("revocation", {})

            return CertificateVerificationResult(
                success=True,
                subject=payload.get("sub", f"{self.issuer}:mock:user123"),
                issuer=payload.get("iss", self.issuer),
                jti=payload.get("jti", str(uuid.uuid4())),
                agent_public_key=agent.get("public_key"),
                agent_public_key_alg=agent.get("public_key_alg", "RS256"),
                claims=claims,
                principal_type=principal.get("type", "human"),
                verified_human=principal.get("verified_human", True),
                crl_url=revocation.get("crl_url", f"{self.issuer}/.well-known/crl.json"),
                ocsp_url=revocation.get("ocsp_url"),
            )

        except jwt.ExpiredSignatureError:
            return CertificateVerificationResult(
                success=False,
                error="Certificate has expired",
                error_code="certificate_expired",
            )
        except jwt.InvalidTokenError as e:
            return CertificateVerificationResult(
                success=False,
                error=f"Invalid certificate: {e}",
                error_code="invalid_certificate",
            )

    async def check_revocation(
        self, jti: str, crl_url: str | None = None
    ) -> RevocationCheckResult:
        """Check if a certificate is revoked.

        For testing, checks against the revoked_certificates list.
        """
        is_revoked = jti in self._revoked_certificates
        return RevocationCheckResult(
            is_revoked=is_revoked,
            checked_at=datetime.now(UTC).isoformat(),
            revoked_at=datetime.now(UTC).isoformat() if is_revoked else None,
            reason="user_requested" if is_revoked else None,
        )

    def create_mock_certificate(
        self,
        agent_public_key_pem: str,
        subject: str | None = None,
        claims: dict[str, Any] | None = None,
        expires_in_days: int = 90,
    ) -> str:
        """Create a mock certificate for testing.

        Args:
            agent_public_key_pem: The agent's public key in PEM format
            subject: Optional subject identifier
            claims: Optional claims to include
            expires_in_days: Certificate validity period

        Returns:
            JWT certificate string
        """
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=expires_in_days)
        jti = str(uuid.uuid4())

        payload = {
            "iss": self.issuer,
            "sub": subject or f"{self.issuer}:mock:user123",
            "iat": now,
            "exp": expires_at,
            "jti": jti,
            "paip_cert": {
                "version": "2.0",
                "type": "agent_certificate",
                "agent": {
                    "public_key": agent_public_key_pem,
                    "public_key_alg": "RS256",
                    "name": "Test Agent",
                },
                "principal": {
                    "type": "human",
                    "verified_human": True,
                    "verification_method": "mock",
                    "verified_at": now.isoformat(),
                },
                "claims": claims or self._mock_claims.copy(),
                "revocation": {
                    "crl_url": f"{self.issuer}/.well-known/crl.json",
                },
            },
        }

        return jwt.encode(
            payload,
            self._private_key,
            algorithm="RS256",
            headers={"kid": "mock-key-1"},
        )

    def revoke_certificate(self, jti: str) -> None:
        """Revoke a certificate by JTI (for testing)."""
        self._revoked_certificates.add(jti)


def create_plugin(config: dict[str, Any]) -> MockIdentityPlugin:
    """Factory function to create a MockIdentityPlugin.

    Args:
        config: Plugin configuration

    Returns:
        Configured MockIdentityPlugin instance
    """
    return MockIdentityPlugin(
        mock_claims=config.get("mock_claims"),
        revoked_certificates=config.get("revoked_certificates"),
    )
