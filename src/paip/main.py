"""PAIP Server Entry Point."""

import argparse
import sys

import uvicorn

from paip import __version__
from paip.tokens import generate_rsa_keypair


def main() -> None:
    """Main entry point for the PAIP server."""
    parser = argparse.ArgumentParser(
        description="Personal Agent Identification Protocol (PAIP) Server"
    )
    parser.add_argument(
        "--version", action="version", version=f"paip-server {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Server command
    serve_parser = subparsers.add_parser("serve", help="Start the PAIP server")
    serve_parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)"
    )
    serve_parser.add_argument(
        "--port", type=int, default=8080, help="Port to bind to (default: 8080)"
    )
    serve_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )

    # Generate keys command
    keygen_parser = subparsers.add_parser("generate-keys", help="Generate RSA keypair")
    keygen_parser.add_argument(
        "--private-key",
        default="keys/private.pem",
        help="Path for private key (default: keys/private.pem)",
    )
    keygen_parser.add_argument(
        "--public-key",
        default="keys/public.pem",
        help="Path for public key (default: keys/public.pem)",
    )

    args = parser.parse_args()

    if args.command == "serve":
        uvicorn.run(
            "paip.server:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
        )
    elif args.command == "generate-keys":
        print(f"Generating RSA keypair...")
        print(f"  Private key: {args.private_key}")
        print(f"  Public key: {args.public_key}")
        generate_rsa_keypair(args.private_key, args.public_key)
        print("Done!")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
