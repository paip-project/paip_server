"""PAIP Request/Response Models."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# === Certificate Models ===


class AgentCertificateAgent(BaseModel):
    """Agent information within a certificate."""

    public_key: str = Field(..., description="Agent's public key (PEM format)")
    public_key_alg: str = Field(default="RS256", description="Algorithm for the public key")
    name: str | None = Field(default=None, description="Human-readable agent name")


class AgentCertificatePrincipal(BaseModel):
    """Principal (human/org) information within a certificate."""

    type: str = Field(..., description="'human' or 'organization'")
    verified_human: bool = Field(..., description="Whether identity was verified")
    verification_method: str = Field(..., description="How verification was performed")
    verified_at: datetime | None = Field(default=None, description="When verification occurred")


class AgentCertificateRevocation(BaseModel):
    """Revocation information within a certificate."""

    crl_url: str = Field(..., description="URL for Certificate Revocation List")
    ocsp_url: str | None = Field(default=None, description="URL for OCSP endpoint")


class AgentCertificateConstraints(BaseModel):
    """Constraints on certificate usage."""

    scopes: list[str] | None = Field(default=None, description="Allowed scopes")
    max_audience: str | None = Field(default=None, description="Maximum audience scope")


class PAIPCertPayload(BaseModel):
    """The paip_cert field within an agent certificate."""

    version: str = Field(default="2.0", description="PAIP protocol version")
    type: str = Field(default="agent_certificate", description="Certificate type")
    agent: AgentCertificateAgent
    principal: AgentCertificatePrincipal
    claims: dict[str, Any] | None = Field(default=None, description="Additional verified claims")
    constraints: AgentCertificateConstraints | None = Field(default=None)
    revocation: AgentCertificateRevocation


# === Handshake Models ===


class HandshakeRequest(BaseModel):
    """Request body for the /handshake endpoint (v2.0 certificate-based)."""

    certificate: str = Field(..., description="Agent certificate JWT signed by IdP")
    audience: str = Field(..., description="The website this token will be used for")
    timestamp: str = Field(..., description="ISO 8601 timestamp (must be within 5 minutes)")
    nonce: str = Field(..., description="Random string to prevent replay attacks")
    signature: str = Field(..., description="Agent's signature over '{audience}|{timestamp}|{nonce}'")


class HandshakeErrorDetail(BaseModel):
    """Error details for handshake failures."""

    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")


class HandshakeResponse(BaseModel):
    """Response body for the /handshake endpoint."""

    success: bool
    session_token: str | None = None
    expires_at: datetime | None = None
    claims: dict[str, Any] | None = None
    error: HandshakeErrorDetail | None = None


# === Verification Models ===


class VerifyRequest(BaseModel):
    """Request body for the /verify endpoint."""

    token: str = Field(..., description="PAIP session token to verify")


class VerifyErrorDetail(BaseModel):
    """Error details for verification failures."""

    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")


class VerifyResponse(BaseModel):
    """Response body for the /verify endpoint."""

    valid: bool
    claims: dict[str, Any] | None = None
    idp: str | None = None
    subject: str | None = None
    expires_at: datetime | None = None
    error: VerifyErrorDetail | None = None


# === Discovery Models ===


class IdentityProviderInfo(BaseModel):
    """Identity provider information for discovery."""

    issuer: str
    name: str
    description: str | None = None


class AgentAPIInfo(BaseModel):
    """API endpoint information for discovery."""

    path: str
    method: str
    description: str | None = None
    required_claims: list[str] = Field(default_factory=list)


class DiscoveryDocument(BaseModel):
    """PAIP discovery document (/.well-known/paip.json)."""

    version: str = "2.0"
    name: str
    paip_server: str
    trusted_identity_providers: list[IdentityProviderInfo]
    required_claims: list[str] = Field(default_factory=list)
    agent_apis: list[AgentAPIInfo] = Field(default_factory=list)


# === CRL Models ===


class RevokedCertificate(BaseModel):
    """A revoked certificate entry."""

    jti: str = Field(..., description="Certificate JTI")
    revoked_at: datetime = Field(..., description="When certificate was revoked")
    reason: str = Field(..., description="Revocation reason")


class CertificateRevocationList(BaseModel):
    """Certificate Revocation List."""

    issuer: str = Field(..., description="IdP issuer URL")
    updated_at: datetime = Field(..., description="When CRL was last updated")
    next_update: datetime = Field(..., description="When CRL will be updated next")
    revoked_certificates: list[RevokedCertificate] = Field(default_factory=list)


# === JWKS Models ===


class JWK(BaseModel):
    """JSON Web Key."""

    kty: str = Field(..., description="Key type")
    kid: str = Field(..., description="Key ID")
    use: str = Field(default="sig", description="Key use")
    alg: str = Field(..., description="Algorithm")
    n: str = Field(..., description="RSA modulus (base64url)")
    e: str = Field(..., description="RSA exponent (base64url)")


class JWKS(BaseModel):
    """JSON Web Key Set."""

    keys: list[JWK]


# === Health Models ===


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str
