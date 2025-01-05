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
WEB3_PROVIDER_URL = os.getenv('WEB3_PROVIDER_URL', 'https://eth-mainnet.alchemyapi.io/v2/YOUR_ALCHEMY_API_KEY')
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
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Disable password authentication
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Disable public key authentication
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'keyboard-interactive'

    def check_auth_keyboard_interactive(self, username, submethods, details):
        # Generate a unique nonce (challenge) for this authentication attempt
        nonce = secrets.token_hex(16)
        self.nonce = nonce
        NONCE_MAP[self.client_address] = nonce
        logger.info(f"Generated nonce for {self.client_address}: {nonce}")

        # Return PARTIALLY_SUCCESSFUL to indicate keyboard-interactive is required
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def get_username(self):
        return self.username

def handle_client(client_socket, client_address):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(host_key)
    server = WalletAuthServer(client_address[0])

    try:
        transport.start_server(server=server)
    except paramiko.SSHException as e:
        logger.error(f"SSH negotiation failed with {client_address}: {e}")
        return

    # Wait for authentication
    channel = transport.accept(20)
    if channel is None:
        logger.warning(f"No channel for {client_address}")
        return

    if not transport.is_authenticated():
        logger.warning(f"Authentication failed for {client_address}")
        channel.close()
        return

    username = server.get_username()
    logger.info(f"User '{username}' authenticated from {client_address}")

    # Retrieve the nonce and wait for the signature
    nonce = NONCE_MAP.get(client_address[0])
    if not nonce:
        logger.warning(f"No nonce found for {client_address}")
        channel.send("Authentication failed.\n")
        channel.close()
        return

    try:
        # Send the prompt to the client
        prompt = f"Please sign this message to authenticate: {nonce}\n"
        channel.send(prompt)
        logger.debug(f"Sent nonce to {client_address}: {nonce}")

        # Receive the signature from the client
        signature = channel.recv(1024).decode('utf-8').strip()
        logger.debug(f"Received signature from {client_address}: {signature}")

        if not signature:
            logger.warning(f"No signature received from {client_address}")
            channel.send("Authentication failed.\n")
            channel.close()
            return

        # Verify the signature
        try:
            recovered_address = w3.eth.account.recover_message(
                encode_defunct(text=nonce),
                signature=signature
            )
            recovered_address = recovered_address.lower()
            logger.info(f"Recovered Address: {recovered_address} from {client_address}")
        except Exception as e:
            logger.error(f"Signature verification error from {client_address}: {e}")
            channel.send("Authentication failed.\n")
            channel.close()
            return

        # Check if the recovered address is in the mapping
        user = WALLET_USER_MAP.get(recovered_address)
        if user:
            logger.info(f"Authentication successful for user: {user} from {client_address}")
            channel.send(f"Welcome {user}! You are authenticated via your crypto wallet.\n")
        else:
            logger.warning(f"Authentication failed: Unknown wallet address {recovered_address} from {client_address}")
            channel.send("Authentication failed.\n")
            channel.close()
            return

        # Provide instructions for the interactive shell
        channel.send("Type 'exit' to close the connection.\n")

        # Start interactive shell
        while True:
            channel.send("shell> ")
            data = channel.recv(1024).decode('utf-8').strip()
            if not data:
                break
            logger.debug(f"Received command from {user}@{client_address}: {data}")
            if data.lower() == 'exit':
                channel.send("Goodbye!\n")
                channel.close()
                logger.info(f"Connection closed for {user}@{client_address}")
                break
            else:
                response = f"You typed: {data}\n"
                channel.send(response)
    except Exception as e:
        logger.error(f"Exception handling client {client_address}: {e}")
    finally:
        transport.close()

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(100)
    logger.info(f"SSH Wallet Authentication Server listening on {HOST}:{PORT} ...")

    while True:
        try:
            client, addr = sock.accept()
            logger.info(f"Incoming connection from {addr[0]}:{addr[1]}")
            client_thread = threading.Thread(target=handle_client, args=(client, addr))
            client_thread.daemon = True
            client_thread.start()
        except KeyboardInterrupt:
            logger.info("Server shutting down.")
            sock.close()
            sys.exit(0)
        except Exception as e:
            logger.error(f"Server error: {e}")

if __name__ == "__main__":
    start_server()
