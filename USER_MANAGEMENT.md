
# SFTP User Management

This document outlines the process for managing users for the SFTP service.

## User Management Overview

User access to the SFTP server is managed through a **Custom Identity Provider**, which is an AWS Lambda function that integrates with AWS Secrets Manager. Each SFTP user has a corresponding secret in Secrets Manager that stores their configuration and credentials.

The process is partially automated using a Terraform module, with a manual step for setting passwords to accommodate existing user credentials.

## End-to-End Authentication Flow

The following steps outline the end-to-end authentication flow for an SFTP user:

1.  **Connection Attempt**: A user attempts to connect to the AWS Transfer Family SFTP server using their SFTP client.
2.  **Custom Identity Provider Invocation**: The AWS Transfer Family service is configured to use a custom identity provider. When a login attempt occurs, it triggers an AWS Lambda function, passing the username and password (if provided).
3.  **Secret Retrieval**: The Lambda function constructs the name of the secret in AWS Secrets Manager based on the provided username (e.g., `prod/sftp/<username>`). It then retrieves this secret.
4.  **Authentication**: The Lambda function verifies the user's credentials:
    *   **For password authentication**, it compares the provided password with the `Password` value in the secret.
    *   **For public key authentication**, it relies on the AWS Transfer Family service to compare the user's private key with the `SshPublicKey` stored in the secret.
5.  **Successful Authentication**: If the credentials are valid, the Lambda function returns a response to the AWS Transfer Family service that includes:
    *   The user's IAM `Role`.
    *   The user's `HomeDirectory` and `HomeDirectoryDetails`.
    *   The AWS Transfer Family service then grants the user access to the SFTP server with the specified IAM role and home directory.
6.  **Failed Authentication**: If the credentials are not valid, the Lambda function returns an error, and the AWS Transfer Family service denies access to the user.

## User Provisioning Process

To provision a new SFTP user, follow these steps:

1.  **Create a User Secret with Terraform**:
    *   Use the provided Terraform module to create a new secret in AWS Secrets Manager.
    *   The secret name must follow the convention: `SECRET_PREFIX/<username>`. The default `SECRET_PREFIX` is `prod/sftp`. For example, a user named `johndoe` would have a secret named `prod/sftp/johndoe`.
    *   The Terraform module will populate the secret with all the necessary information **except for the password**.

2.  **Manually Add the Password to the Secret**:
    *   After the secret is created, you must manually add the user's password to the secret.
    *   This is done by editing the secret in the AWS Secrets Manager console and adding a new key-value pair.
    *   The key must be `Password`, and the value should be the user's password.
    *   This manual step is in place to allow users to use their existing passwords without having them stored in Terraform state.

## User Authentication Methods

The SFTP service supports two methods of authentication:

*   **Password Authentication**: Users can log in using their username and password. The password stored in the `Password` field of the user's secret is used for verification.
*   **SSH Public Key Authentication**: Users can authenticate using an SSH key pair. The public key must be added to the `SshPublicKey` field in the user's secret.

A user can be configured to use either password or SSH key authentication, or both.

## Secret Configuration

The JSON structure of the secret in AWS Secrets Manager must contain the following keys:

| Key | Description | Required |
| :--- | :--- | :--- |
| `Role` | The ARN of the IAM role the user will assume upon successful login. | Yes |
| `HomeDirectory` | The user's landing directory in the S3 bucket. | Yes |
| `HomeDirectoryDetails` | The user's home directory details, used for logical home directories. This allows you to map a user's home directory to a path that is different from the literal path in S3. | Yes |
| `HomeDirectoryType` | The type of home directory. This should be set to `LOGICAL`. | Yes |
| `Password` | The user's password. This is added manually after the secret is created by Terraform. | No (unless SSH key is not used) |
| `SshPublicKey` | The user's SSH public key for key-based authentication. | No (unless password is not used) |

**Example Secret Structure:**
```json
{
  "Role": "arn:aws:iam::123456789012:role/sftp-user-role",
  "HomeDirectory": "/bucket-name/home/johndoe",
  "HomeDirectoryDetails": "[{"Entry":"/","Target":"/bucket-name/home/johndoe"}]",
  "HomeDirectoryType": "LOGICAL",
  "Password": "user-password-added-manually",
  "SshPublicKey": "ssh-rsa AAAA..."
}
```

## User Deprovisioning

To deprovision a user and revoke their SFTP access, simply delete their corresponding secret from AWS Secrets Manager. This can be done via the Terraform module by removing the user's resource block and applying the changes.
