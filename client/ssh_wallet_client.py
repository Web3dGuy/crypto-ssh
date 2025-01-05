# client/ssh_wallet_client.py

import paramiko
import sys
import logging
import socket
from dotenv import load_dotenv
import os
from web3 import Web3, Account
from eth_account.messages import encode_defunct

# Load environment variables
load_dotenv()

# Configure Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# SSH Server Configuration
SERVER_HOST = os.getenv('SERVER_HOST', '10.0.0.153')
SERVER_PORT = int(os.getenv('SERVER_PORT', 2200))

# User Wallet Credentials
WALLET_ADDRESS = os.getenv('WALLET_ADDRESS', '').lower()
PRIVATE_KEY = os.getenv('PRIVATE_KEY', '')

if not WALLET_ADDRESS or not PRIVATE_KEY:
    logger.error("WALLET_ADDRESS and PRIVATE_KEY must be set in .env")
    sys.exit(1)

# Initialize Web3
w3 = Web3()

# Known authentication message
AUTH_MESSAGE = "SSH Authentication"

def authenticate_with_wallet(message):
    """
    Signs the message using the private key.
    """
    try:
        logger.debug(f"Authenticating with wallet. Message to sign: {message}")
        # Sign the message using the private key
        message_encoded = encode_defunct(text=message)
        signed_message = Account.sign_message(message_encoded, private_key=PRIVATE_KEY)
        signature = '0x' + signed_message.signature.hex()
        logger.debug(f"Generated signature: {signature}")
        return signature
    except Exception as e:
        logger.error(f"Error during signing: {e}")
        return None

def interactive_shell(channel):
    """
    Provides an interactive shell session to the user.
    """
    try:
        logger.info("Entering interactive shell.")
        while True:
            data = channel.recv(1024).decode('utf-8')
            if not data:
                logger.info("No more data received. Exiting interactive shell.")
                break
            sys.stdout.write(data)
            if 'shell> ' in data:
                user_input = input()
                channel.send(user_input + '\n')
                logger.debug(f"Sent command to server: {user_input}")
                if user_input.lower() == 'exit':
                    logger.info("Exit command received. Closing interactive shell.")
                    break
    except Exception as e:
        logger.error(f"Interactive shell error: {e}")
    finally:
        channel.close()
        logger.info("Interactive shell closed.")

def main():
    transport = None
    try:
        # Create a socket and connect to the server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.info(f"Attempting to connect to SSH server at {SERVER_HOST}:{SERVER_PORT}...")
        sock.connect((SERVER_HOST, SERVER_PORT))
        logger.info(f"Connected to SSH server at {SERVER_HOST}:{SERVER_PORT}")

        # Initialize Transport
        transport = paramiko.Transport(sock)
        transport.start_client()
        logger.info("Transport layer initialized and client started.")

        # Generate signature for AUTH_MESSAGE
        signature = authenticate_with_wallet(AUTH_MESSAGE)
        if not signature:
            logger.error("Failed to generate signature.")
            transport.close()
            sys.exit(1)

        # Perform password-based authentication, using signature as password
        logger.info("Initiating password-based authentication with signature as password...")
        transport.auth_password(
            username='walletuser',  # The username should match the server's mapping
            password=signature
        )
        logger.info("Authentication attempted.")

        if not transport.is_authenticated():
            logger.error("Authentication failed.")
            transport.close()
            sys.exit(1)

        logger.info("Authentication successful.")

        # Open a session and invoke shell
        channel = transport.open_session()
        channel.invoke_shell()
        logger.info("Interactive shell session started.")

        # Start interactive shell
        interactive_shell(channel)

    except paramiko.AuthenticationException:
        logger.error("Authentication failed.")
        sys.exit(1)
    except paramiko.SSHException as e:
        logger.error(f"SSH connection failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Connection error: {e}")
        sys.exit(1)
    finally:
        if transport:
            transport.close()
            logger.info("SSH transport closed.")
        logger.info("SSH connection closed.")

if __name__ == "__main__":
    main()
