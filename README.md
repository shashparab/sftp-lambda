# SFTP Lambda Authentication

This project implements an AWS Lambda function for custom user authentication for an AWS Transfer Family SFTP server.

## Project Structure

```
.
├── README.md
├── requirements.txt
├── src
│   ├── lambda_function.py
│   └── sftp_authenticator.py
└── tests
```

## How it Works

The `lambda_handler` function in `src/lambda_function.py` is the entry point for the Lambda function. It is triggered when a user attempts to log in to the SFTP server.

The authentication process is as follows:

1.  The Lambda function receives the username and password (if provided) from the AWS Transfer Family service.
2.  It constructs the name of the secret to retrieve from AWS Secrets Manager based on the username and a prefix (e.g., `prod/sftp/<username>`).
3.  The `SFTPAuthenticator` class in `src/sftp_authenticator.py` is used to retrieve the secret from AWS Secrets Manager.
4.  The `authenticate_user` method in `SFTPAuthenticator` verifies the provided password against the `Password` stored in the secret. It also supports public key authentication using the `SshPublicKey` from the secret.
5.  If authentication is successful, the `construct_success_response` method creates a response that grants the user access to the SFTP server. This response includes the user's IAM `Role`, `HomeDirectory`, `HomeDirectoryDetails`, and `HomeDirectoryType`, all retrieved from the secret.
6.  If authentication fails, an `AuthenticationError` is raised, which causes the AWS Transfer Family service to deny access to the user.

## Installation

To install the dependencies, run:

```bash
pip install -r requirements.txt
```

## Configuration

-   **AWS Secrets Manager**: User data is stored in AWS Secrets Manager. The secret should be a JSON object with the following keys:
    -   `Password`: The user's password for password authentication.
    -   `SshPublicKey`: The user's SSH public key for public key authentication.
    -   `Role`: The ARN of the IAM role to assume.
    -   `HomeDirectory`: The user's landing directory.
    -   `HomeDirectoryDetails`: The user's home directory details, used for logical home directories.
    -   `HomeDirectoryType`: The type of home directory, e.g., `LOGICAL`.
-   **IAM Role**: The Lambda function assumes an IAM role that grants it permission to access AWS Secrets Manager.
-   **Environment Variables**:
    -   `SECRET_PREFIX`: The prefix for the secret names in AWS Secrets Manager. Defaults to `prod/sftp`.