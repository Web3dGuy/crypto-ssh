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

def authenticate_with_wallet(prompt):
    """
    Extracts the nonce from the prompt and signs it with the private key.
    """
    try:
        logger.debug(f"Authenticating with wallet. Prompt received: {prompt}")
        # Extract the nonce from the prompt
        # Expected format: "Please sign this message to authenticate: <nonce>"
        if "Please sign this message to authenticate:" in prompt:
            nonce = prompt.split(':')[-1].strip()
            logger.info(f"Received nonce to sign: {nonce}")
        else:
            logger.error("Unexpected prompt format.")
            return None

        # Sign the nonce using the private key
        message = nonce
        # Encode the message as defunct to ensure compatibility
        message_encoded = encode_defunct(text=message)
        signed_message = Account.sign_message(message_encoded, private_key=PRIVATE_KEY)
        signature = '0x' + signed_message.signature.hex()
        logger.debug(f"Generated signature: {signature}")
        return signature
    except Exception as e:
        logger.error(f"Error during signing: {e}")
        return None

def keyboard_interactive_handler(title, instructions, prompt_list):
    """
    Handler for keyboard-interactive authentication.
    Extracts the nonce, signs it, and returns the signature.
    """
    logger.debug("Keyboard-interactive authentication handler invoked.")
    responses = []
    for prompt, echo in prompt_list:
        logger.debug(f"Prompt received: {prompt} | Echo: {echo}")
        if "Please sign this message to authenticate:" in prompt:
            signature = authenticate_with_wallet(prompt)
            if signature:
                logger.debug("Appending signature to responses.")
                responses.append(signature)
            else:
                logger.debug("Appending empty string to responses due to failed signature generation.")
                responses.append('')
        else:
            logger.debug("Appending empty string to responses for unknown prompts.")
            responses.append('')
    logger.debug(f"Responses to send: {responses}")
    return responses

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

        # Perform keyboard-interactive authentication
        logger.info("Initiating keyboard-interactive authentication...")
        transport.auth_interactive(
            username='walletuser',
            handler=keyboard_interactive_handler
        )
        logger.info("Authentication attempted.")

        if not transport.is_authenticated():
            logger.error("Authentication failed.")
            transport.close()
            sys.exit(1)

        logger.info("Authentication successful.")

        # Open a session
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
