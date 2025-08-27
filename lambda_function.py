"""
AWS Lambda function for custom identity provider for AWS Transfer Family SFTP.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class AuthenticationError(Exception):
    """Custom exception for authentication failures."""


def get_secret(secret_name: str) -> Dict[str, Any]:
    """
    Retrieves a secret from AWS Secrets Manager.

    Args:
        secret_name: The name of the secret to retrieve.

    Returns:
        The secret data as a dictionary.

    Raises:
        AuthenticationError: If the secret cannot be found or another error occurs.
    """
    secrets_manager_client = boto3.client("secretsmanager")
    try:
        secret_response = secrets_manager_client.get_secret_value(SecretId=secret_name)
        secret_string = secret_response["SecretString"]
        return json.loads(secret_string)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.error("Secret not found for user")
            raise AuthenticationError("User not found or credentials invalid.") from e
        logger.error("An unexpected error occurred: %s", e)
        raise AuthenticationError("An unexpected error occurred.") from e


def authenticate_user(
    password: Optional[str], secret_data: Dict[str, Any]
) -> None:
    """
    Authenticates the user based on the provided password or SSH public key.

    Args:
        password: The password provided by the client (if any).
        secret_data: The secret data for the user.

    Raises:
        AuthenticationError: If authentication fails.
    """
    if password:
        if password != secret_data.get("password"):
            raise AuthenticationError("Invalid credentials.")
        logger.info("Password authentication successful.")
    else:
        if "ssh_public_key" not in secret_data:
            raise AuthenticationError("No public key configured for user.")
        logger.info("Proceeding with public key authentication.")


def construct_success_response(
    username: str, secret_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Constructs the success response for AWS Transfer Family.

    Args:
        username: The username of the authenticated user.
        secret_data: The secret data for the user.

    Returns:
        A dictionary with the user details for AWS Transfer Family.
    """
    role = secret_data["iam_role"]
    home_directory_base = os.environ.get("HOME_DIRECTORY_BASE", "/sftp-home")
    home_directory_details = [
        {"Entry": "/", "Target": f"{home_directory_base}/{username}"}
    ]

    response: Dict[str, Any] = {
        "Role": role,
        "HomeDirectoryType": "LOGICAL",
        "HomeDirectoryDetails": home_directory_details,
    }

    if "ssh_public_key" in secret_data:
        response["PublicKeys"] = [secret_data["ssh_public_key"]]

    return response


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
        secret_data = get_secret(secret_name)
        authenticate_user(password, secret_data)
        response = construct_success_response(username, secret_data)
        logger.info("Successfully authenticated user %s.", username)
        return response
    except AuthenticationError as e:
        logger.error("Authentication failed: %s", e)
        # Re-raise the exception to ensure the authentication fails in Transfer Family
        raise e