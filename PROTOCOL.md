# Personal Agent Identification Protocol (PAIP)

**Version:** 2.0-draft
**Status:** Draft
**Last Updated:** January 2025

## Abstract

The Personal Agent Identification Protocol (PAIP) establishes a standardized framework for verifying that automated agents represent authenticated, real humans (or organizations) when interacting with web APIs. PAIP enables websites to become "agent-ready" by defining which identity providers they trust and what verification is required for API access.

PAIP draws inspiration from the TLS/SSL certificate model, treating Identity Providers as Certificate Authorities that issue agent credentials.

## Table of Contents

1. [Introduction](#1-introduction)
2. [The Certificate Authority Analogy](#2-the-certificate-authority-analogy)
3. [Terminology](#3-terminology)
4. [Protocol Overview](#4-protocol-overview)
5. [Agent Certificates](#5-agent-certificates)
6. [Identity Provider Requirements](#6-identity-provider-requirements)
7. [Discovery](#7-discovery)
8. [Handshake](#8-handshake)
9. [Session Tokens](#9-session-tokens)
10. [Token Verification](#10-token-verification)
11. [Claims](#11-claims)
12. [Security Considerations](#12-security-considerations)
13. [Examples](#13-examples)

---

## 1. Introduction

### 1.1 Problem Statement

As AI agents become increasingly capable of interacting with web services on behalf of users, websites face a fundamental trust problem: **how do they know an agent represents a real person?**

Consider a dermatology clinic that wants to allow patients' AI agents to book appointments. If they expose a booking API without verification:

- **Spam and abuse:** Bots could fill appointment slots with fake bookings
- **No accountability:** No way to trace actions back to real people
- **Fraud risk:** Malicious actors could impersonate patients
- **Resource waste:** Staff time spent on fake appointments

The clinic needs a way to say: *"I will only accept bookings from agents that can prove they represent a verified human."*

### 1.2 The Trust Problem

This is analogous to a problem the web solved decades ago: **how does your browser know it's really talking to your bank?**

The solution was **TLS certificates** issued by **Certificate Authorities (CAs)**. Your browser trusts certain CAs, and when a website presents a certificate signed by a trusted CA, the browser knows the site is legitimate.

PAIP applies this same model to agent identity:

| TLS/Web | PAIP/Agents |
|---------|-------------|
| Website needs to prove identity | Agent needs to prove it represents a real person |
| Certificate Authority verifies website | Identity Provider verifies human identity |
| CA issues certificate to website | IdP issues certificate to agent |
| Browser trusts certain CAs | Website trusts certain IdPs |
| Certificate contains public key | Agent certificate contains agent's public key |
| Website proves identity by signing with private key | Agent proves identity by signing with private key |

### 1.3 Solution

PAIP provides a certificate-based framework where:

1. **Identity Providers (IdPs)** verify that humans are real (via documents, biometrics, etc.)
2. **IdPs issue Agent Certificates** binding an agent's public key to a verified human identity
3. **Websites declare which IdPs they trust** (like browsers trust certain CAs)
4. **Agents prove their identity** by presenting their certificate and signing requests with their private key
5. **PAIP servers issue short-lived session tokens** after verifying the certificate chain

### 1.4 Design Principles

- **Certificate-based:** Long-lived credentials that don't require constant re-authentication
- **Cryptographically secure:** Stolen certificates are useless without the agent's private key
- **Revocable:** Certificates can be revoked instantly if compromised
- **Decentralized trust:** Websites choose which IdPs to trust, no central authority
- **Privacy-preserving:** Agents can prove identity without revealing unnecessary details

---

## 2. The Certificate Authority Analogy

### 2.1 How TLS Works

```
┌─────────────────┐
│   Root CA       │  (DigiCert, Let's Encrypt, etc.)
│   (Trusted)     │
└────────┬────────┘
         │ Signs
         ▼
┌─────────────────┐
│  TLS Certificate│  (example.com's cert)
│  - Domain name  │
│  - Public key   │
│  - Expiry date  │
│  - CA signature │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  TLS Handshake  │  Server proves it controls the certificate
│                 │  by signing with its private key
└─────────────────┘
```

**Key insight:** The certificate is long-lived (90 days to 1 year), but the server proves ownership in real-time by using its private key. No "login" or "password" - just possession of the private key.

### 2.2 How PAIP Works

```
┌─────────────────┐
│ Identity        │  (Arbor ID, World ID, ID.me, etc.)
│ Provider (IdP)  │  Verifies humans are real
└────────┬────────┘
         │ Signs
         ▼
┌─────────────────┐
│ Agent           │  (Jane's AI Assistant)
│ Certificate     │
│  - Human ID     │  "This agent belongs to verified human Jane"
│  - Agent pub key│
│  - Expiry (90d) │
│  - IdP signature│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ PAIP Handshake  │  Agent proves it holds the certificate
│                 │  by signing with its private key
└─────────────────┘
```

### 2.3 Why This Model?

**Traditional OAuth tokens:**
```
User logs in → Gets token → Token expires → User logs in again
```
- Requires user interaction for every token refresh
- Token theft = immediate compromise

**Certificate model:**
```
User verifies once → IdP signs agent certificate → Certificate valid 90 days
Agent uses private key to prove identity → No re-login needed
```
- User only involved at certificate issuance
- Certificate theft is useless without private key
- Instant revocation possible

---

## 3. Terminology

| Term | Definition |
|------|------------|
| **Agent** | An automated system (typically AI-powered) acting on behalf of a human or organization |
| **Agent Certificate** | A JWT signed by an IdP that binds an agent's public key to a verified identity |
| **Website** | A web service that wants to accept agent requests from verified humans |
| **PAIP Server** | The server that verifies agent certificates and issues session tokens |
| **Identity Provider (IdP)** | A service that verifies human identity and issues agent certificates (analogous to a Certificate Authority) |
| **Trust Anchor** | An IdP's public key, used to verify certificates it has signed |
| **Session Token** | A short-lived JWT issued by the PAIP server after certificate verification |
| **Claims** | Verified attributes about the human (e.g., `verified_human`, `full_name`) |
| **Revocation** | The process of invalidating a certificate before its expiry |

---

## 4. Protocol Overview

### 4.1 Architecture

```
┌──────────┐       ┌──────────────┐       ┌─────────────┐
│  Agent   │       │  PAIP Server │       │    IdP      │
└────┬─────┘       └──────┬───────┘       └──────┬──────┘
     │                    │                      │
     │ 1. Agent has certificate from IdP         │
     │    (obtained during one-time setup)       │
     │                    │                      │
     │ 2. GET /.well-known/paip.json             │
     │    (discover trusted IdPs)                │
     │                    │                      │
     │ 3. POST /handshake │                      │
     │    - certificate   │                      │
     │    - signature     │                      │
     │───────────────────>│                      │
     │                    │                      │
     │                    │ 4. Verify:           │
     │                    │    - Cert signature  │
     │                    │    - Cert not expired│
     │                    │    - Cert not revoked│
     │                    │    - Agent signature │
     │                    │────────────────────> │
     │                    │    (check revocation)│
     │                    │                      │
     │ 5. Session token   │                      │
     │    (1 hour, scoped)│                      │
     │<───────────────────│                      │
     │                    │                      │
┌────▼─────────────┐      │                      │
│     Website      │      │                      │
│     Backend      │      │                      │
└────────┬─────────┘      │                      │
         │                │                      │
         │ 6. Agent makes API calls with         │
         │    session token                      │
         │                │                      │
         │ 7. Backend verifies token             │
         │    (locally or via /verify)           │
```

### 4.2 Flow Summary

1. **Certificate Issuance (one-time):** Human verifies identity with IdP, registers agent's public key, receives signed certificate
2. **Discovery:** Agent fetches website's PAIP configuration to learn trusted IdPs
3. **Handshake:** Agent presents certificate and proves possession of private key
4. **Verification:** PAIP server verifies certificate chain and revocation status
5. **Token Issuance:** PAIP server issues short-lived session token
6. **API Access:** Agent includes session token in requests to website
7. **Validation:** Website validates session token

---

## 5. Agent Certificates

Agent certificates are JWTs signed by Identity Providers that bind an agent's public key to a verified human identity.

### 5.1 Certificate Format

Agent certificates are JSON Web Tokens (JWT) with the following structure:

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "<idp-key-id>"
}
```

**Payload:**
```json
{
  "iss": "https://arbor.id",
  "sub": "arbor:jane_doe_abc123",
  "iat": 1704067200,
  "exp": 1711843200,
  "jti": "cert-uuid-here",

  "paip_cert": {
    "version": "2.0",
    "type": "agent_certificate",

    "agent": {
      "public_key": "-----BEGIN PUBLIC KEY-----\nMIIB...",
      "public_key_alg": "RS256",
      "name": "Jane's AI Assistant"
    },

    "principal": {
      "type": "human",
      "verified_human": true,
      "verification_method": "document_plus_liveness",
      "verified_at": "2025-01-01T12:00:00Z"
    },

    "claims": {
      "full_name": "Jane Doe",
      "email": "jane@example.com",
      "email_verified": true
    },

    "constraints": {
      "scopes": ["booking", "scheduling"],
      "max_audience": null
    },

    "revocation": {
      "crl_url": "https://arbor.id/.well-known/crl.json",
      "ocsp_url": "https://arbor.id/ocsp"
    }
  }
}
```

### 5.2 Certificate Fields

| Field | Required | Description |
|-------|----------|-------------|
| `iss` | Yes | IdP's issuer URL |
| `sub` | Yes | Subject identifier (format: `{idp}:{user_id}`) |
| `iat` | Yes | Issued at timestamp |
| `exp` | Yes | Expiration timestamp (max 90 days from issuance) |
| `jti` | Yes | Unique certificate identifier (for revocation) |
| `paip_cert.version` | Yes | PAIP protocol version |
| `paip_cert.type` | Yes | Must be `"agent_certificate"` |
| `paip_cert.agent.public_key` | Yes | Agent's public key (PEM format) |
| `paip_cert.agent.public_key_alg` | Yes | Algorithm for the public key |
| `paip_cert.agent.name` | No | Human-readable agent name |
| `paip_cert.principal.type` | Yes | `"human"` or `"organization"` |
| `paip_cert.principal.verified_human` | Yes | Whether identity was verified |
| `paip_cert.principal.verification_method` | Yes | How verification was performed |
| `paip_cert.claims` | No | Additional verified claims |
| `paip_cert.constraints.scopes` | No | Allowed scopes for this agent |
| `paip_cert.revocation.crl_url` | Yes | URL for Certificate Revocation List |
| `paip_cert.revocation.ocsp_url` | No | URL for Online Certificate Status Protocol |

### 5.3 Certificate Lifetime

- Certificates MUST NOT exceed 90 days validity
- IdPs SHOULD default to 90 days
- Certificates MUST be re-issued (with user approval) upon expiration
- Certificates MAY be revoked before expiration

---

## 6. Identity Provider Requirements

To be PAIP-compatible, Identity Providers must implement the following.

### 6.1 Trust Anchor Publication

IdPs MUST publish their public keys at a well-known URL:

```
GET https://{idp}/.well-known/jwks.json
```

Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "arbor-2025-01",
      "use": "sig",
      "alg": "RS256",
      "n": "<modulus>",
      "e": "<exponent>"
    }
  ]
}
```

### 6.2 Certificate Revocation List (CRL)

IdPs MUST publish a Certificate Revocation List:

```
GET https://{idp}/.well-known/crl.json
```

Response:
```json
{
  "issuer": "https://arbor.id",
  "updated_at": "2025-01-04T12:00:00Z",
  "next_update": "2025-01-04T13:00:00Z",
  "revoked_certificates": [
    {
      "jti": "cert-uuid-1",
      "revoked_at": "2025-01-03T10:00:00Z",
      "reason": "user_requested"
    },
    {
      "jti": "cert-uuid-2",
      "revoked_at": "2025-01-02T15:00:00Z",
      "reason": "key_compromise"
    }
  ]
}
```

CRL SHOULD be updated at least hourly. PAIP servers SHOULD cache the CRL and refresh periodically.

### 6.3 Online Certificate Status Protocol (OCSP) - Optional

IdPs MAY provide an OCSP endpoint for real-time revocation checking:

```
GET https://{idp}/ocsp/{certificate_jti}
```

Response:
```json
{
  "jti": "cert-uuid-here",
  "status": "valid",
  "checked_at": "2025-01-04T15:30:00Z"
}
```

Status values: `valid`, `revoked`, `unknown`

### 6.4 IdP Metadata

IdPs SHOULD publish metadata at:

```
GET https://{idp}/.well-known/paip-idp.json
```

Response:
```json
{
  "issuer": "https://arbor.id",
  "name": "Arbor ID",
  "description": "Document-verified human identity for AI agents",
  "jwks_uri": "https://arbor.id/.well-known/jwks.json",
  "crl_uri": "https://arbor.id/.well-known/crl.json",
  "ocsp_uri": "https://arbor.id/ocsp",
  "supported_claims": [
    "verified_human",
    "full_name",
    "email",
    "email_verified"
  ],
  "verification_methods": [
    "document_plus_liveness",
    "document_only"
  ],
  "certificate_max_lifetime_days": 90
}
```

---

## 7. Discovery

Websites publish their PAIP configuration at a well-known URL.

### 7.1 Discovery Endpoint

```
GET https://{website}/.well-known/paip.json
```

### 7.2 Discovery Document Schema

```json
{
  "version": "2.0",
  "name": "Dr. Smith's Dermatology",
  "paip_server": "https://paip.drsmith-derm.com",
  "trusted_identity_providers": [
    {
      "issuer": "https://arbor.id",
      "name": "Arbor ID",
      "jwks_uri": "https://arbor.id/.well-known/jwks.json",
      "required_verification_methods": ["document_plus_liveness"]
    },
    {
      "issuer": "https://id.worldcoin.org",
      "name": "World ID",
      "jwks_uri": "https://id.worldcoin.org/.well-known/jwks.json"
    }
  ],
  "required_claims": ["verified_human", "full_name"],
  "agent_apis": [
    {
      "path": "/api/schedule",
      "method": "POST",
      "description": "Book an appointment",
      "required_claims": ["verified_human", "full_name"]
    },
    {
      "path": "/api/availability",
      "method": "GET",
      "description": "Check available slots",
      "required_claims": []
    }
  ]
}
```

---

## 8. Handshake

The handshake proves the agent holds a valid certificate and the corresponding private key.

### 8.1 Handshake Request

```
POST https://{paip_server}/handshake
Content-Type: application/json

{
  "certificate": "<agent certificate JWT>",
  "audience": "https://drsmith-derm.com",
  "timestamp": "2025-01-04T15:30:00Z",
  "nonce": "random-nonce-abc123",
  "signature": "<agent signs {audience, timestamp, nonce} with private key>"
}
```

### 8.2 Handshake Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `certificate` | string | Yes | The agent certificate JWT signed by the IdP |
| `audience` | string | Yes | The website this session token will be used for |
| `timestamp` | string | Yes | ISO 8601 timestamp (must be within 5 minutes of server time) |
| `nonce` | string | Yes | Random string to prevent replay attacks |
| `signature` | string | Yes | Agent's signature over `{audience}\|{timestamp}\|{nonce}` using its private key |

### 8.3 Signature Generation

The agent signs the concatenation of audience, timestamp, and nonce:

```
message = f"{audience}|{timestamp}|{nonce}"
signature = sign(message, agent_private_key)
signature_b64 = base64url_encode(signature)
```

### 8.4 Handshake Verification

The PAIP server performs the following checks:

1. **Parse certificate:** Decode the JWT
2. **Verify IdP signature:** Check certificate is signed by a trusted IdP
3. **Check expiration:** Certificate must not be expired
4. **Check revocation:** Certificate must not be on the CRL (or OCSP check)
5. **Verify agent signature:** Decode signature, verify it matches the message using the public key from the certificate
6. **Check timestamp:** Must be within 5 minutes of server time
7. **Check required claims:** Certificate must contain all claims required by the website

### 8.5 Handshake Response (Success)

```json
{
  "success": true,
  "session_token": "<PAIP-signed JWT>",
  "expires_at": "2025-01-04T16:30:00Z",
  "claims": {
    "verified_human": true,
    "full_name": "Jane Doe"
  }
}
```

### 8.6 Handshake Response (Failure)

```json
{
  "success": false,
  "error": {
    "code": "certificate_revoked",
    "message": "The agent certificate has been revoked"
  }
}
```

### 8.7 Handshake Error Codes

| Code | Description |
|------|-------------|
| `untrusted_idp` | Certificate was signed by an IdP not trusted by this website |
| `certificate_expired` | The agent certificate has expired |
| `certificate_revoked` | The agent certificate has been revoked |
| `invalid_certificate_signature` | The IdP signature on the certificate is invalid |
| `invalid_agent_signature` | The agent's signature does not match |
| `timestamp_invalid` | Timestamp is too far from server time |
| `missing_required_claims` | Certificate does not contain required claims |
| `invalid_audience` | The requested audience is not configured |

---

## 9. Session Tokens

After successful handshake, the PAIP server issues a short-lived session token.

### 9.1 Token Structure

```json
{
  "iss": "https://paip.drsmith-derm.com",
  "sub": "arbor:jane_doe_abc123",
  "aud": "https://drsmith-derm.com",
  "exp": 1704369600,
  "iat": 1704366000,
  "jti": "session-uuid-here",

  "paip": {
    "version": "2.0",
    "idp": "https://arbor.id",
    "certificate_jti": "cert-uuid-here",
    "claims": {
      "verified_human": true,
      "full_name": "Jane Doe"
    }
  }
}
```

### 9.2 Token Lifetime

- Session tokens expire **1 hour** after issuance
- Tokens are scoped to a **single audience** (website)
- Agents must perform a new handshake when tokens expire
- No refresh mechanism - the certificate-based handshake is lightweight

---

## 10. Token Verification

Websites can verify session tokens using two methods.

### 10.1 Local Verification (Recommended)

Fetch the PAIP server's public keys and verify locally:

```
GET https://{paip_server}/.well-known/jwks.json
```

### 10.2 API Verification

For backends without JWT libraries:

```
POST https://{paip_server}/verify
Content-Type: application/json

{
  "token": "<PAIP session token>"
}
```

Response:
```json
{
  "valid": true,
  "claims": {
    "verified_human": true,
    "full_name": "Jane Doe"
  },
  "idp": "https://arbor.id",
  "subject": "arbor:jane_doe_abc123",
  "expires_at": "2025-01-04T16:30:00Z"
}
```

---

## 11. Claims

### 11.1 Standard Claims

| Claim | Type | Description |
|-------|------|-------------|
| `verified_human` | boolean | IdP has verified this is a real person |
| `full_name` | string | Person's full legal name |
| `email` | string | Email address |
| `email_verified` | boolean | Whether email was verified |
| `phone` | string | Phone number |
| `phone_verified` | boolean | Whether phone was verified |
| `organization` | string | Organization name (for org-type principals) |

### 11.2 Namespaced Claims

IdPs may provide additional domain-specific claims:

```json
{
  "verified_human": true,
  "full_name": "Jane Doe",

  "https://arbor.id/claims": {
    "verification_level": "enhanced",
    "document_type": "passport"
  }
}
```

---

## 12. Security Considerations

### 12.1 Private Key Security

- Agent private keys MUST be stored securely (not in plain text)
- Recommended: Hardware security modules, OS keychains, or cloud KMS
- Private keys MUST NEVER be transmitted

### 12.2 Certificate Theft

Unlike OAuth tokens, stolen certificates are **useless without the private key**:

| Stolen Item | Risk |
|-------------|------|
| Session token only | 1 hour of access to one website |
| Certificate only | Cannot generate valid signatures |
| Certificate + private key | Full impersonation until revoked |

### 12.3 Revocation

- IdPs MUST support instant revocation
- PAIP servers MUST check revocation status during handshake
- Users SHOULD be able to revoke certificates via IdP dashboard

### 12.4 Replay Attacks

The handshake includes timestamp and nonce to prevent replay:

- Timestamp must be within 5 minutes of server time
- Nonce ensures each handshake request is unique
- PAIP servers MAY track recent nonces to reject duplicates

### 12.5 Transport Security

- All endpoints MUST use HTTPS
- TLS 1.2+ REQUIRED

---

## 13. Examples

### 13.1 Complete Flow

**Scenario:** Jane wants her AI agent to book a dermatology appointment.

**One-time setup (already completed):**
1. Jane verified her identity with Arbor ID (document + liveness check)
2. Jane's agent generated a keypair
3. Jane registered the agent's public key with Arbor ID
4. Arbor ID issued a 90-day agent certificate

**Booking flow:**

```
Step 1: Agent discovers requirements
─────────────────────────────────────
GET https://drsmith-derm.com/.well-known/paip.json

Response:
{
  "version": "2.0",
  "name": "Dr. Smith's Dermatology",
  "paip_server": "https://paip.drsmith-derm.com",
  "trusted_identity_providers": [
    {"issuer": "https://arbor.id", "name": "Arbor ID"}
  ],
  "required_claims": ["verified_human", "full_name"]
}


Step 2: Agent performs handshake
─────────────────────────────────────
POST https://paip.drsmith-derm.com/handshake
{
  "certificate": "eyJhbGciOiJSUzI1NiIs...",
  "audience": "https://drsmith-derm.com",
  "timestamp": "2025-01-04T15:30:00Z",
  "nonce": "abc123xyz",
  "signature": "base64-signature..."
}

Response:
{
  "success": true,
  "session_token": "eyJhbGciOiJSUzI1NiIs...",
  "expires_at": "2025-01-04T16:30:00Z",
  "claims": {"verified_human": true, "full_name": "Jane Doe"}
}


Step 3: Agent books appointment
─────────────────────────────────────
POST https://drsmith-derm.com/api/schedule
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
{
  "date": "2025-01-15",
  "time": "10:00",
  "reason": "Annual skin check"
}

Response:
{
  "success": true,
  "appointment_id": "APT-12345"
}
```

---

## Appendix A: PAIP Server API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwks.json` | PAIP server's public keys |
| `POST` | `/handshake` | Exchange certificate for session token |
| `POST` | `/verify` | Verify a session token |
| `GET` | `/health` | Server health check |

---

## Appendix B: IdP API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwks.json` | IdP's public keys (trust anchors) |
| `GET` | `/.well-known/crl.json` | Certificate Revocation List |
| `GET` | `/.well-known/paip-idp.json` | IdP metadata |
| `GET` | `/ocsp/{jti}` | Online certificate status (optional) |

---

## Appendix C: Supported Algorithms

### Signing Algorithms

| Algorithm | Support Level |
|-----------|---------------|
| `RS256` | REQUIRED |
| `ES256` | RECOMMENDED |
| `Ed25519` | OPTIONAL |

### Key Types

| Type | Support Level |
|------|---------------|
| RSA (2048+ bits) | REQUIRED |
| EC (P-256) | RECOMMENDED |
| OKP (Ed25519) | OPTIONAL |

---

## Appendix D: References

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 5280 - X.509 PKI Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
- [RFC 6960 - Online Certificate Status Protocol (OCSP)](https://tools.ietf.org/html/rfc6960)
