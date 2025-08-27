
import json
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """
    AWS Lambda function for custom identity provider for AWS Transfer Family SFTP.

    This function authenticates users for an SFTP server using credentials
    stored in AWS Secrets Manager. It supports both password and SSH public
    key authentication.

    Args:
        event (dict): The event payload from AWS Transfer Family. It contains:
            - server_id (str): The unique identifier of the Transfer Family server.
            - username (str): The username of the connecting client.
            - password (str, optional): The password provided by the client.
            - protocol (str): The protocol used for connection (e.g., 'SFTP').
        context (object): The Lambda runtime information. Not used in this function.

    Returns:
        dict: A dictionary with user details if authentication is successful.
              The dictionary must conform to the AWS Transfer Family identity
              provider response format.

    Raises:
        Exception: If authentication fails for any reason (user not found,
                   invalid credentials, etc.).
    """
    print(f"Received event: {json.dumps(event)}")

    # Extract username and password from the event
    username = event.get('username')
    password = event.get('password')
    server_id = event.get('server_id')

    if not username or not server_id:
        raise Exception('Authentication failed: Username or Server ID missing from event.')

    # Construct the secret name based on the username
    # Example: for username 'sftpuser', the secret name is 'prod/sftp/sftpuser'
    secret_name = f"prod/sftp/{username}"

    # Initialize the Boto3 client for Secrets Manager
    secrets_manager_client = boto3.client('secretsmanager')

    try:
        # Retrieve the secret from AWS Secrets Manager
        secret_response = secrets_manager_client.get_secret_value(
            SecretId=secret_name
        )
        secret_string = secret_response['SecretString']
        secret_data = json.loads(secret_string)

        # --- Authentication Logic ---

        # Case 1: Password authentication
        if password:
            if password == secret_data.get('password'):
                print(f"Password authentication successful for user: {username}")
            else:
                raise Exception('Authentication failed: Invalid credentials.')
        # Case 2: SSH public key authentication
        # If no password is provided, we assume public key auth is intended.
        # The Transfer Family service will handle the key validation.
        # We just need to provide the stored public key.
        else:
            print(f"Proceeding with public key authentication for user: {username}")
            if 'ssh_public_key' not in secret_data:
                raise Exception('Authentication failed: No public key configured for user.')

        # --- Construct Success Response ---

        # The IAM role that the user will assume for S3 access
        role = secret_data['iam_role']

        # Define the user's home directory.
        # HomeDirectoryType 'LOGICAL' allows mapping a user-friendly path ('/')
        # to a specific S3 bucket and prefix.
        # TODO: The 'Target' should be dynamically constructed based on the
        # username or other business logic, e.g., f"/sftp-home/{username}"
        home_directory_details = [
            {
                "Entry": "/",
                "Target": f"/sftp-home/{username}"
            }
        ]

        response = {
            "Role": role,
            "HomeDirectoryType": "LOGICAL",
            "HomeDirectoryDetails": home_directory_details
        }

        # Include public keys if they exist in the secret
        if 'ssh_public_key' in secret_data:
            response["PublicKeys"] = [secret_data['ssh_public_key']]

        print(f"Successfully authenticated user {username}. Returning response.")
        return response

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Secret not found for user: {username}")
        else:
            print(f"An unexpected error occurred: {e}")
        raise Exception('User not found or credentials invalid.')
    except Exception as e:
        print(f"Authentication failed: {e}")
        raise Exception('User not found or credentials invalid.')

