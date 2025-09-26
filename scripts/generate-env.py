#!/usr/bin/env python3
"""
Script to generate secure .env file from .env-example template.

This script helps developers set up secure configuration by:
1. Copying .env-example to .env if it doesn't exist
2. Generating secure secrets for production use
3. Providing guidance for external API keys
"""

import secrets
import string
from pathlib import Path


def generate_secret_key(length: int = 64) -> str:
    """Generate a cryptographically secure secret key."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_password(length: int = 32) -> str:
    """Generate a secure password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main():
    """Generate .env file with secure defaults."""
    project_root = Path(__file__).parent.parent
    env_example = project_root / ".env-example"
    env_file = project_root / ".env"

    # Check if .env already exists
    if env_file.exists():
        response = input(f"{env_file} already exists. Overwrite? (y/N): ")
        if response.lower() != "y":
            print("Aborted.")
            return

    # Read .env-example
    if not env_example.exists():
        print(f"Error: {env_example} not found!")
        return

    with open(env_example) as f:
        content = f.read()

    # Generate secure values
    replacements = {
        "password": generate_password(),
        "change-me-in-production": generate_secret_key(),
        "admin": generate_password(16),  # Grafana admin password
    }

    # Apply replacements
    for old_value, new_value in replacements.items():
        content = content.replace(old_value, new_value)

    # Write .env file
    with open(env_file, "w") as f:
        f.write(content)

    print(f"✅ Generated {env_file} with secure defaults")
    print("\n🔧 Next steps:")
    print("1. Review and update the generated .env file")
    print("2. Add your external API keys (VirusTotal, Shodan, etc.)")
    print("3. Adjust URLs and ports if needed")
    print("4. For production, use strong unique passwords")

    print("\n🔐 Generated secure credentials:")
    print(f"   Database password: {replacements['password']}")
    print(f"   Grafana admin password: {replacements['admin']}")
    print("   (Secret key generated but not displayed for security)")


if __name__ == "__main__":
    main()
