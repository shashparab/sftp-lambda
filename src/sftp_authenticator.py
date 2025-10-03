"""
This module contains the SFTPAuthenticator class, which is responsible for
authenticating users for the SFTP server.
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Custom exception for authentication failures."""


class SFTPAuthenticator:
    """Authenticates users for the SFTP server."""

    def __init__(self, secrets_manager_client: Any, cache_ttl_seconds: int = 300) -> None:
        """
        Initializes the SFTPAuthenticator.

        Args:
            secrets_manager_client: The Boto3 Secrets Manager client.
            cache_ttl_seconds: The Time-to-Live for the in-memory secret cache.
        """
        self.secrets_manager_client = secrets_manager_client
        self._cache: Dict[str, Any] = {}
        self._cache_ttl = cache_ttl_seconds

    def get_secret(self, secret_name: str) -> Dict[str, Any]:
        """
        Retrieves a secret from AWS Secrets Manager, using an in-memory cache.

        Args:
            secret_name: The name of the secret to retrieve.

        Returns:
            The secret data as a dictionary.

        Raises:
            AuthenticationError: If the secret cannot be found or another error occurs.
        """
        # Check cache first
        if secret_name in self._cache:
            cached_item = self._cache[secret_name]
            if (time.time() - cached_item["timestamp"]) < self._cache_ttl:
                logger.info("Returning secret for user '%s' from cache.", secret_name)
                return cached_item["data"]
            logger.info("Cache expired for user '%s'.", secret_name)

        logger.info("Fetching secret for user '%s' from AWS Secrets Manager.", secret_name)
        try:
            secret_response = self.secrets_manager_client.get_secret_value(
                SecretId=secret_name
            )
            secret_string = secret_response["SecretString"]
            secret_data = json.loads(secret_string)

            # Store in cache
            self._cache[secret_name] = {"timestamp": time.time(), "data": secret_data}

            return secret_data
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.error("Secret not found for user")
                raise AuthenticationError(
                    "User not found or credentials invalid."
                ) from e
            logger.error("An unexpected error occurred: %s", e)
            raise AuthenticationError("An unexpected error occurred.") from e

    def authenticate_user(
        self, password: Optional[str], secret_data: Dict[str, Any]
    ) -> None:
        """
        Authenticates the user based on the provided password or SSH public key.

        Args:
            password: The password provided by the client (if any).
            secret_data: The secret data for the user.

        Raises:
            AuthenticationError: If authentication fails.
        """
        if "Password" not in secret_data and "SshPublicKeys" not in secret_data:
            raise AuthenticationError(
                "No 'Password' or 'SshPublicKeys' configured for user."
            )
        if password:
            if password != secret_data.get("Password"):
                raise AuthenticationError("Invalid credentials.")
            logger.info("Password authentication successful.")
        else:
            if "SshPublicKeys" not in secret_data:
                raise AuthenticationError("No public key configured for user.")
            logger.info("Proceeding with public key authentication.")

    def construct_success_response(
        self,
        username: str,
        secret_data: Dict[str, Any],
        password_provided: bool = False,
    ) -> Dict[str, Any]:
        """
        Constructs the success response for AWS Transfer Family.

        Args:
            username: The username of the authenticated user.
            secret_data: The secret data for the user.
            password_provided: True if a password was provided for authentication.

        Returns:
            A dictionary with the user details for AWS Transfer Family.

        Raises:
            AuthenticationError: If a mandatory field is not found in the secret data.
        """
        response = {}

        # Mandatory fields from secret
        for field in ["Role", "HomeDirectory", "HomeDirectoryDetails", "HomeDirectoryType"]:
            if field not in secret_data:
                raise AuthenticationError(f"'{field}' not configured for user {username}")
            response[field] = secret_data[field]

        # Optional: Public Keys. Only include if password was not used for auth.
        if not password_provided and "SshPublicKeys" in secret_data:
            response["PublicKeys"] = secret_data["SshPublicKeys"]

        return response

    def invalidate_cache(self, secret_name: str) -> None:
        """
        Invalidates the cache for a specific secret.

        Args:
            secret_name: The name of the secret to invalidate.
        """
        if secret_name in self._cache:
            del self._cache[secret_name]
            logger.info("Invalidated cache for secret '%s'.", secret_name)