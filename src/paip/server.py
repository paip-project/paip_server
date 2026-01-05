"""PAIP FastAPI Server."""

import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from paip import __version__
from paip.config import PAIPConfig, SiteConfig, load_config, Settings
from paip.models import (
    JWKS,
    HandshakeErrorDetail,
    HandshakeRequest,
    HandshakeResponse,
    HealthResponse,
    VerifyErrorDetail,
    VerifyRequest,
    VerifyResponse,
)
from paip.plugin_interface import PluginRegistry
from paip.tokens import TokenManager, verify_agent_signature, validate_timestamp

logger = logging.getLogger(__name__)


class PAIPServer:
    """PAIP Server application."""

    def __init__(self, config: PAIPConfig, settings: Settings):
        """Initialize the PAIP server.

        Args:
            config: PAIP configuration
            settings: Environment settings
        """
        self.config = config
        self.settings = settings
        self.plugin_registry = PluginRegistry()
        self.token_manager: TokenManager | None = None
        self._sites_by_audience: dict[str, SiteConfig] = {}

    def setup(self) -> None:
        """Set up the server (load keys, register plugins)."""
        # Initialize token manager
        self.token_manager = TokenManager(
            private_key_path=self.config.keys.private_key_path,
            public_key_path=self.config.keys.public_key_path,
            key_id=self.config.keys.key_id,
            issuer=f"https://paip.local",  # TODO: Make configurable
        )

        # Index sites by audience
        for site in self.config.sites:
            self._sites_by_audience[site.audience] = site

        # Load and register plugins
        self._load_plugins()

    def _load_plugins(self) -> None:
        """Load IdP plugins from configuration."""
        for idp_config in self.config.identity_providers:
            plugin_name = idp_config.plugin

            # Import plugin module
            try:
                if plugin_name == "mock":
                    from paip.plugins.mock import create_plugin

                    plugin = create_plugin(idp_config.config)
                else:
                    # Dynamic import for external plugins
                    import importlib

                    module = importlib.import_module(f"paip.plugins.{plugin_name}")
                    plugin = module.create_plugin(idp_config.config)

                self.plugin_registry.register(plugin)
                logger.info(f"Loaded IdP plugin: {plugin.name} ({plugin.issuer})")

            except ImportError as e:
                logger.error(f"Failed to load plugin '{plugin_name}': {e}")
                raise

    def get_site_config(self, audience: str) -> SiteConfig | None:
        """Get site configuration by audience URL."""
        return self._sites_by_audience.get(audience)

    def is_idp_trusted_for_site(self, idp: str, site: SiteConfig) -> bool:
        """Check if an IdP is trusted for a given site."""
        # Look up the IdP plugin
        plugin = self.plugin_registry.get(idp)
        if plugin is None:
            return False

        # Check if this IdP's id is in the site's trusted providers
        for idp_config in self.config.identity_providers:
            if plugin.issuer == idp:
                return idp_config.id in site.trusted_providers

        return False


# Global server instance (set during lifespan)
_server: PAIPServer | None = None


def get_server() -> PAIPServer:
    """Get the global server instance."""
    if _server is None:
        raise RuntimeError("Server not initialized")
    return _server


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global _server

    settings = Settings()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Load configuration
    config = load_config(settings.config_path, settings.secrets_path)

    # Create and setup server
    _server = PAIPServer(config, settings)
    _server.setup()

    logger.info(f"PAIP Server v{__version__} started")
    logger.info(f"Loaded {len(_server.plugin_registry.list_plugins())} IdP plugins")
    logger.info(f"Configured {len(_server.config.sites)} sites")

    yield

    logger.info("PAIP Server shutting down")


# Create FastAPI app
app = FastAPI(
    title="PAIP Server",
    description="Personal Agent Identification Protocol Server",
    version=__version__,
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure per deployment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# === Endpoints ===


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="healthy", version=__version__)


@app.get("/.well-known/jwks.json", response_model=JWKS)
async def get_jwks() -> JWKS:
    """Get JSON Web Key Set for local token verification."""
    server = get_server()
    if server.token_manager is None:
        raise HTTPException(status_code=500, detail="Token manager not initialized")
    return server.token_manager.get_jwks()


@app.post("/handshake", response_model=HandshakeResponse)
async def handshake(request: HandshakeRequest) -> HandshakeResponse:
    """Exchange an agent certificate for a PAIP session token.

    The certificate-based handshake flow:
    1. Verify timestamp is within 5 minutes
    2. Decode certificate to find issuer
    3. Check IdP is trusted for this site
    4. Verify certificate signature using IdP's public key
    5. Check certificate revocation status
    6. Verify agent's signature over the handshake message
    7. Check required claims
    8. Issue session token
    """
    server = get_server()

    # Step 1: Validate timestamp
    if not validate_timestamp(request.timestamp):
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="timestamp_invalid",
                message="Timestamp is too far from server time (max 5 minutes skew)",
            ),
        )

    # Step 2: Decode certificate to find issuer (without verification first)
    try:
        unverified = jwt.decode(request.certificate, options={"verify_signature": False})
        issuer = unverified.get("iss")
        if not issuer:
            return HandshakeResponse(
                success=False,
                error=HandshakeErrorDetail(
                    code="invalid_certificate",
                    message="Certificate missing issuer (iss) claim",
                ),
            )
    except jwt.InvalidTokenError as e:
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="invalid_certificate",
                message=f"Invalid certificate format: {e}",
            ),
        )

    # Step 3: Validate audience (site must be configured)
    site = server.get_site_config(request.audience)
    if site is None:
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="invalid_audience",
                message=f"Site not configured: {request.audience}",
            ),
        )

    # Step 4: Check if IdP is trusted for this site
    if not server.is_idp_trusted_for_site(issuer, site):
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="untrusted_idp",
                message=f"Identity provider not trusted for this site: {issuer}",
            ),
        )

    # Step 5: Get the IdP plugin
    plugin = server.plugin_registry.get(issuer)
    if plugin is None:
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="invalid_idp",
                message=f"Unknown identity provider: {issuer}",
            ),
        )

    # Step 6: Verify the certificate signature
    try:
        cert_result = await plugin.verify_certificate(request.certificate)
    except Exception as e:
        logger.exception(f"Certificate verification failed: {e}")
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="certificate_verification_failed",
                message="Certificate verification failed",
            ),
        )

    if not cert_result.success:
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code=cert_result.error_code or "invalid_certificate_signature",
                message=cert_result.error or "Certificate verification failed",
            ),
        )

    # Step 7: Check certificate revocation
    try:
        revocation_result = await plugin.check_revocation(
            cert_result.jti,
            cert_result.crl_url,
        )
        if revocation_result.is_revoked:
            return HandshakeResponse(
                success=False,
                error=HandshakeErrorDetail(
                    code="certificate_revoked",
                    message=f"Certificate has been revoked: {revocation_result.reason}",
                ),
            )
    except Exception as e:
        logger.warning(f"Revocation check failed (allowing): {e}")
        # Continue - revocation check failure shouldn't block valid certs

    # Step 8: Verify agent's signature over the handshake message
    if not cert_result.agent_public_key:
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="invalid_certificate",
                message="Certificate missing agent public key",
            ),
        )

    if not verify_agent_signature(
        audience=request.audience,
        timestamp=request.timestamp,
        nonce=request.nonce,
        signature_b64=request.signature,
        public_key_pem=cert_result.agent_public_key,
        algorithm=cert_result.agent_public_key_alg or "RS256",
    ):
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="invalid_agent_signature",
                message="Agent signature verification failed",
            ),
        )

    # Step 9: Check required claims
    claims = cert_result.claims or {}
    # Add verified_human from principal if present
    if cert_result.verified_human:
        claims["verified_human"] = True

    missing_claims = [c for c in site.required_claims if c not in claims]
    if missing_claims:
        return HandshakeResponse(
            success=False,
            error=HandshakeErrorDetail(
                code="missing_required_claims",
                message=f"Missing required claims: {', '.join(missing_claims)}",
            ),
        )

    # Step 10: Create session token
    if server.token_manager is None:
        raise HTTPException(status_code=500, detail="Token manager not initialized")

    token, expires_at = server.token_manager.create_session_token(
        subject=cert_result.subject,
        audience=request.audience,
        idp=issuer,
        claims=claims,
        certificate_jti=cert_result.jti,
    )

    return HandshakeResponse(
        success=True,
        session_token=token,
        expires_at=expires_at,
        claims=claims,
    )


@app.post("/verify", response_model=VerifyResponse)
async def verify_token(request: VerifyRequest) -> VerifyResponse:
    """Verify a PAIP session token."""
    server = get_server()

    if server.token_manager is None:
        raise HTTPException(status_code=500, detail="Token manager not initialized")

    try:
        payload = server.token_manager.verify_session_token(request.token)
    except jwt.ExpiredSignatureError:
        return VerifyResponse(
            valid=False,
            error=VerifyErrorDetail(
                code="token_expired",
                message="The session token has expired",
            ),
        )
    except jwt.InvalidAudienceError:
        return VerifyResponse(
            valid=False,
            error=VerifyErrorDetail(
                code="invalid_audience",
                message="The token was issued for a different website",
            ),
        )
    except jwt.InvalidIssuerError:
        return VerifyResponse(
            valid=False,
            error=VerifyErrorDetail(
                code="invalid_issuer",
                message="The token was not issued by this PAIP server",
            ),
        )
    except jwt.InvalidTokenError as e:
        return VerifyResponse(
            valid=False,
            error=VerifyErrorDetail(
                code="malformed_token",
                message=str(e),
            ),
        )

    # Extract PAIP claims
    paip_data = payload.get("paip", {})
    claims = paip_data.get("claims", {})
    idp = paip_data.get("idp")

    return VerifyResponse(
        valid=True,
        claims=claims,
        idp=idp,
        subject=payload.get("sub"),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
    )


def create_app() -> FastAPI:
    """Create the FastAPI application.

    This is useful for testing or custom deployments.
    """
    return app
