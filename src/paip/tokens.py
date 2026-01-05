"""JWT Token Management for PAIP."""

import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from paip.models import JWK, JWKS

# Token lifetime in seconds (1 hour)
TOKEN_LIFETIME_SECONDS = 3600

# Maximum timestamp skew in seconds (5 minutes)
MAX_TIMESTAMP_SKEW_SECONDS = 300


class TokenManager:
    """Manages JWT token creation and verification."""

    def __init__(self, private_key_path: str, public_key_path: str, key_id: str, issuer: str):
        """Initialize the token manager.

        Args:
            private_key_path: Path to RSA private key PEM file
            public_key_path: Path to RSA public key PEM file
            key_id: Key ID for JWKS
            issuer: Issuer URL for tokens
        """
        self.key_id = key_id
        self.issuer = issuer

        # Load keys
        self._private_key = self._load_private_key(private_key_path)
        self._public_key = self._load_public_key(public_key_path)

    def _load_private_key(self, path: str) -> rsa.RSAPrivateKey:
        """Load RSA private key from PEM file."""
        key_path = Path(path)
        if not key_path.exists():
            raise FileNotFoundError(f"Private key not found: {path}")

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Key must be an RSA private key")

        return key

    def _load_public_key(self, path: str) -> rsa.RSAPublicKey:
        """Load RSA public key from PEM file."""
        key_path = Path(path)
        if not key_path.exists():
            raise FileNotFoundError(f"Public key not found: {path}")

        with open(key_path, "rb") as f:
            key = serialization.load_pem_public_key(f.read())

        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("Key must be an RSA public key")

        return key

    def create_session_token(
        self,
        subject: str,
        audience: str,
        idp: str,
        claims: dict[str, Any],
        certificate_jti: str | None = None,
    ) -> tuple[str, datetime]:
        """Create a PAIP session token.

        Args:
            subject: Subject identifier (format: {idp}:{user_id})
            audience: The website this token is for
            idp: The identity provider that verified the user
            claims: Verified claims about the user
            certificate_jti: JTI of the certificate used for authentication

        Returns:
            Tuple of (token string, expiration datetime)
        """
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=TOKEN_LIFETIME_SECONDS)

        paip_data = {
            "version": "2.0",
            "idp": idp,
            "claims": claims,
        }
        if certificate_jti:
            paip_data["certificate_jti"] = certificate_jti

        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "exp": expires_at,
            "iat": now,
            "jti": str(uuid.uuid4()),
            "paip": paip_data,
        }

        token = jwt.encode(
            payload,
            self._private_key,
            algorithm="RS256",
            headers={"kid": self.key_id},
        )

        return token, expires_at

    def verify_session_token(self, token: str, audience: str | None = None) -> dict[str, Any]:
        """Verify a PAIP session token.

        Args:
            token: The JWT token to verify
            audience: Optional audience to validate against

        Returns:
            Decoded token payload

        Raises:
            jwt.InvalidTokenError: If token is invalid
        """
        options = {}
        if audience is None:
            options["verify_aud"] = False

        return jwt.decode(
            token,
            self._public_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=self.issuer,
            options=options,
        )

    def get_jwks(self) -> JWKS:
        """Get the JSON Web Key Set for public key distribution."""
        public_numbers = self._public_key.public_numbers()

        # Convert to base64url encoding
        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, byteorder="big"
        )
        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, byteorder="big"
        )

        n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")
        e_b64 = base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode("ascii")

        jwk = JWK(
            kty="RSA",
            kid=self.key_id,
            use="sig",
            alg="RS256",
            n=n_b64,
            e=e_b64,
        )

        return JWKS(keys=[jwk])


def generate_rsa_keypair(private_key_path: str, public_key_path: str) -> None:
    """Generate a new RSA keypair and save to files.

    Args:
        private_key_path: Path to save private key
        public_key_path: Path to save public key
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(private_key_path).parent.mkdir(parents=True, exist_ok=True)
    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    # Save public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(public_key_path).parent.mkdir(parents=True, exist_ok=True)
    with open(public_key_path, "wb") as f:
        f.write(public_pem)


def verify_agent_signature(
    audience: str,
    timestamp: str,
    nonce: str,
    signature_b64: str,
    public_key_pem: str,
    algorithm: str = "RS256",
) -> bool:
    """Verify an agent's signature over the handshake message.

    The message format is: "{audience}|{timestamp}|{nonce}"

    Args:
        audience: The target website URL
        timestamp: ISO 8601 timestamp
        nonce: Random nonce string
        signature_b64: Base64url-encoded signature
        public_key_pem: Agent's public key in PEM format
        algorithm: Signature algorithm (RS256 or ES256)

    Returns:
        True if signature is valid, False otherwise
    """
    # Construct the message
    message = f"{audience}|{timestamp}|{nonce}"
    message_bytes = message.encode("utf-8")

    # Decode signature from base64url
    # Add padding if needed
    padding_needed = 4 - len(signature_b64) % 4
    if padding_needed != 4:
        signature_b64 += "=" * padding_needed

    try:
        signature = base64.urlsafe_b64decode(signature_b64)
    except Exception:
        return False

    # Load public key
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception:
        return False

    # Verify signature based on algorithm
    try:
        if algorithm in ("RS256", "RS384", "RS512"):
            # RSA signature
            hash_alg = {
                "RS256": hashes.SHA256(),
                "RS384": hashes.SHA384(),
                "RS512": hashes.SHA512(),
            }[algorithm]

            public_key.verify(
                signature,
                message_bytes,
                padding.PKCS1v15(),
                hash_alg,
            )
            return True
        elif algorithm in ("ES256", "ES384", "ES512"):
            # ECDSA signature
            from cryptography.hazmat.primitives.asymmetric import ec

            hash_alg = {
                "ES256": hashes.SHA256(),
                "ES384": hashes.SHA384(),
                "ES512": hashes.SHA512(),
            }[algorithm]

            public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hash_alg),
            )
            return True
        else:
            return False
    except InvalidSignature:
        return False
    except Exception:
        return False


def validate_timestamp(timestamp: str, max_skew_seconds: int = MAX_TIMESTAMP_SKEW_SECONDS) -> bool:
    """Validate that a timestamp is within acceptable skew of current time.

    Args:
        timestamp: ISO 8601 timestamp string
        max_skew_seconds: Maximum allowed difference from current time

    Returns:
        True if timestamp is valid, False otherwise
    """
    try:
        # Parse timestamp
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        # Ensure timezone-aware
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)

        # Compare to current time
        now = datetime.now(UTC)
        diff = abs((now - ts).total_seconds())

        return diff <= max_skew_seconds
    except Exception:
        return False


def create_agent_signature(
    audience: str,
    timestamp: str,
    nonce: str,
    private_key_pem: str,
    algorithm: str = "RS256",
) -> str:
    """Create an agent signature over the handshake message.

    This is a utility function for testing and agent implementations.

    Args:
        audience: The target website URL
        timestamp: ISO 8601 timestamp
        nonce: Random nonce string
        private_key_pem: Agent's private key in PEM format
        algorithm: Signature algorithm (RS256 or ES256)

    Returns:
        Base64url-encoded signature
    """
    # Construct the message
    message = f"{audience}|{timestamp}|{nonce}"
    message_bytes = message.encode("utf-8")

    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )

    # Sign based on algorithm
    if algorithm in ("RS256", "RS384", "RS512"):
        hash_alg = {
            "RS256": hashes.SHA256(),
            "RS384": hashes.SHA384(),
            "RS512": hashes.SHA512(),
        }[algorithm]

        signature = private_key.sign(
            message_bytes,
            padding.PKCS1v15(),
            hash_alg,
        )
    elif algorithm in ("ES256", "ES384", "ES512"):
        from cryptography.hazmat.primitives.asymmetric import ec

        hash_alg = {
            "ES256": hashes.SHA256(),
            "ES384": hashes.SHA384(),
            "ES512": hashes.SHA512(),
        }[algorithm]

        signature = private_key.sign(
            message_bytes,
            ec.ECDSA(hash_alg),
        )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Encode as base64url (without padding)
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
