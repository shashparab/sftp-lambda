"""
AWS Lambda function for custom identity provider for AWS Transfer Family SFTP.
"""

import logging
import os
from typing import Any, Dict

import boto3

from sftp_authenticator import SFTPAuthenticator, AuthenticationError

# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


secrets_manager_client = boto3.client("secretsmanager")
cache_ttl = int(os.environ.get("CACHE_TTL_SECONDS", "300"))
try:
    cache_ttl = int(os.environ.get("CACHE_TTL_SECONDS", "300"))
except (ValueError, TypeError):
    logger.warning("Invalid CACHE_TTL_SECONDS, defaulting to 300.")
    cache_ttl = 300

authenticator = SFTPAuthenticator(secrets_manager_client, cache_ttl_seconds=cache_ttl)


def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """
    AWS Lambda function for custom identity provider for AWS Transfer Family SFTP.

    This function authenticates users for an SFTP server using credentials
    stored in AWS Secrets Manager. It supports both password and SSH public
    key authentication.

    Args:
        event: The event payload from AWS Transfer Family.
        context: The Lambda runtime information.

    Returns:
        A dictionary with user details if authentication is successful.

    Raises:
        AuthenticationError: If authentication fails for any reason.
    """
    logger.info("Received authentication request.")

    username = event.get("username")
    password = event.get("password")
    server_id = event.get("server_id")

    if not username or not server_id:
        raise AuthenticationError(
            "Authentication failed: Username or Server ID missing from event."
        )

    secret_prefix = os.environ.get("SECRET_PREFIX", "prod/sftp")
    secret_name = f"{secret_prefix}/{username}"

    try:
        secret_data = authenticator.get_secret(secret_name)
        authenticator.authenticate_user(password, secret_data)
        response = authenticator.construct_success_response(
            username, secret_data, password_provided=(password is not None)
        )
        logger.info("Successfully authenticated user %s.", username)
        return response
    except AuthenticationError as e:
        logger.error("Authentication failed: %s", e)
        authenticator.invalidate_cache(secret_name)
        # Re-raise the exception to ensure the authentication fails in Transfer Family
        raise e
