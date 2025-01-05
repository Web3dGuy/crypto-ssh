# server/ssh_wallet_server.py

import paramiko
import socket
import threading
import sys
import os
import secrets
import logging
from dotenv import load_dotenv
from web3 import Web3, HTTPProvider
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
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 2200))

# Blockchain Configuration
WEB3_PROVIDER_URL = os.getenv('WEB3_PROVIDER_URL', 'https://eth-mainnet.alchemy.com/v2/YOUR_ALCHEMY_API_KEY')
w3 = Web3(HTTPProvider(WEB3_PROVIDER_URL))
if not w3.is_connected():
    logger.error("Web3 provider is not connected. Check your WEB3_PROVIDER_URL.")
    sys.exit(1)
else:
    logger.info(f"Connected to Web3 provider at {WEB3_PROVIDER_URL}")

# User Wallet Mapping
def parse_wallet_user_map(mapping_str):
    mapping = {}
    entries = mapping_str.split(',')
    for entry in entries:
        try:
            wallet, user = entry.split(':')
            mapping[wallet.lower()] = user
        except ValueError:
            logger.warning(f"Invalid mapping entry: {entry}")
    return mapping

WALLET_USER_MAP = parse_wallet_user_map(os.getenv('WALLET_USER_MAP', ''))

if not WALLET_USER_MAP:
    logger.error("No valid wallet-user mappings found. Please update the WALLET_USER_MAP in .env.")
    sys.exit(1)
else:
    logger.info(f"Loaded wallet-user mappings: {WALLET_USER_MAP}")

# SSH Server Host Key
HOST_KEY_FILE = 'server_host_key.pem'
if not os.path.exists(HOST_KEY_FILE):
    logger.info("Generating SSH host key...")
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(HOST_KEY_FILE)
    logger.info(f"SSH host key generated and saved to {HOST_KEY_FILE}")
else:
    host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)
    logger.info(f"Loaded SSH host key from {HOST_KEY_FILE}")

# Dictionary to store nonces per client address
NONCE_MAP = {}

class WalletAuthServer(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.event = threading.Event()
        self.client_address = client_address
        self.username = None
        self.nonce = None

    def check_channel_request(self, kind, chanid):
        logger.debug(f"Channel request received. Kind: {kind}, ChanID: {chanid}")
        if kind == 'session':
            logger.debug("Session channel accepted.")
            return paramiko.OPEN_SUCCEEDED
        logger.debug("Session channel rejected.")
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Disable password authentication
        logger.debug("Password authentication attempt detected and rejected.")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Disable public key authentication
        logger.debug("Public key authentication attempt detected and rejected.")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        logger.debug(f"Allowed authentication methods requested for user: {username}")
        return 'keyboard-interactive'

    def check_auth_keyboard_interactive(self, username, submethods, details):
        logger.info(f"Keyboard-interactive authentication requested for user: {username}")
        # Generate a unique nonce (challenge) for this authentication attempt
        nonce = secrets.token_hex(16)
        NONCE_MAP[self.client_address] = nonce
        logger.info(f"Generated nonce for {self.client_address}: {nonce}")

        # Define the prompt
        prompts = [("Please sign this message to authenticate:", False)]
        logger.debug(f"Prompts sent to {self.client_address}: {prompts}")

        # Send the prompt to the client
        try:
            self.transport = self.transport  # Access transport
            self.transport.send_message(nonce.encode('utf-8'))
            logger.debug(f"Nonce sent to {self.client_address}")
        except Exception as e:
            logger.error(f"Failed to send nonce to {self.client_address}: {e}")
            return paramiko.AUTH_FAILED

        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_keyboard_interactive_response(self, responses):
        """
        Handle responses from keyboard-interactive authentication.
        """
        logger.debug(f"Received keyboard-interactive responses: {responses}")
        nonce = NONCE_MAP.get(self.client_address)
        if not nonce:
            logger.warning(f"No nonce found for {self.client_address}")
            return paramiko.AUTH_FAILED

        signature = responses[0] if responses else ''
        logger.info(f"Received signature from {self.client_address}: {signature}")

        if not signature:
            logger.warning(f"No signature received from {self.client_address}")
            return paramiko.AUTH_FAILED

        # Verify the signature
        try:
            recovered_address = w3.eth.account.recover_message(
                encode_defunct(text=nonce),
                signature=signature
            )
            recovered_address = recovered_address.lower()
            logger.info(f"Recovered Address: {recovered_address} from {self.client_address}")
        except Exception as e:
            logger.error(f"Signature verification error from {self.client_address}: {e}")
            return paramiko.AUTH_FAILED

        # Check if the recovered address is in the mapping
        user = WALLET_USER_MAP.get(recovered_address)
        if user:
            self.username = user
            logger.info(f"Authentication successful for user: {user} from {self.client_address}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            logger.warning(f"Authentication failed: Unknown wallet address {recovered_address} from {self.client_address}")
            return paramiko.AUTH_FAILED

    def get_username(self):
        return self.username

def handle_client(client_socket, client_address):
    logger.info(f"Incoming connection from {client_address[0]}:{client_address[1]}")
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(host_key)
    server = WalletAuthServer(client_address[0])

    try:
        transport.start_server(server=server)
    except paramiko.SSHException as e:
        logger.error(f"SSH negotiation failed with {client_address}: {e}")
        return

    # Wait for authentication
    try:
        channel = transport.accept(30)
        if channel is None:
            logger.warning(f"No channel established with {client_address}")
            return

        if not transport.is_authenticated():
            logger.warning(f"Authentication failed for {client_address}")
            channel.close()
            return

        username = server.get_username()
        logger.info(f"User '{username}' authenticated from {client_address}")

        # Start interactive shell
        channel.send(f"Welcome {username}! You are authenticated via your crypto wallet.\n")
        channel.send("Type 'exit' to close the connection.\n")
        logger.debug(f"Sent welcome messages to {username}@{client_address}")

        while True:
            channel.send("shell> ")
            logger.debug(f"Sent shell prompt to {username}@{client_address}")
            data = channel.recv(1024).decode('utf-8').strip()
            if not data:
                logger.info(f"No data received from {username}@{client_address}. Closing connection.")
                break
            logger.info(f"Received command from {username}@{client_address}: {data}")
            if data.lower() == 'exit':
                channel.send("Goodbye!\n")
                logger.info(f"Exit command received from {username}@{client_address}. Closing connection.")
                break
            else:
                response = f"You typed: {data}\n"
                channel.send(response)
                logger.debug(f"Sent response to {username}@{client_address}: {response.strip()}")

    except paramiko.SSHException as e:
        logger.error(f"SSH exception with {client_address}: {e}")
    except Exception as e:
        logger.error(f"Exception handling client {client_address}: {e}")
    finally:
        transport.close()
        logger.info(f"Connection closed for {username}@{client_address}")

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(100)
    logger.info(f"SSH Wallet Authentication Server listening on {HOST}:{PORT} ...")

    while True:
        try:
            client, addr = sock.accept()
            client_thread = threading.Thread(target=handle_client, args=(client, addr))
            client_thread.daemon = True
            client_thread.start()
            logger.debug(f"Started thread {client_thread.name} for {addr}")
        except KeyboardInterrupt:
            logger.info("Server shutting down.")
            sock.close()
            sys.exit(0)
        except Exception as e:
            logger.error(f"Server error: {e}")

if __name__ == "__main__":
    start_server()
