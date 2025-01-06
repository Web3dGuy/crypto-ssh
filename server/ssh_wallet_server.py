import paramiko
import socket
import threading
import sys
import os
import logging
from dotenv import load_dotenv
from web3 import Web3, HTTPProvider
from eth_account.messages import encode_defunct
import zipfile
import tarfile
import qrcode
from qrcode.main import QRCode
from io import StringIO
from datetime import datetime

# Load environment variables
load_dotenv()

# Configure Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG').upper()
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

# Server Configuration
SERVER_ROOT = os.path.normpath(os.path.dirname(os.path.abspath(__file__)))
HOME_ROOT = os.path.normpath(os.path.join(SERVER_ROOT, 'home'))
if not os.path.exists(HOME_ROOT):
    os.makedirs(HOME_ROOT, mode=0o755)
    logger.info(f"Created home root directory at {HOME_ROOT}")

def get_user_home(username):
    """Get or create user's home directory."""
    user_home = os.path.normpath(os.path.join(HOME_ROOT, username))
    if not os.path.exists(user_home):
        os.makedirs(user_home, mode=0o755)
        logger.info(f"Created home directory for user {username} at {user_home}")
    return user_home

def get_current_dir(username):
    """Get the current working directory for a user."""
    cwd_key = f'USER_HOME_{username}'
    return os.environ.get(cwd_key, get_user_home(username))

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

# Known authentication message
AUTH_MESSAGE = "SSH Authentication"

class WalletAuthServer(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.event = threading.Event()
        self.client_address = client_address
        self.username = None

    def check_channel_request(self, kind, chanid):
        logger.debug(f"Channel request received. Kind: {kind}, ChanID: {chanid}")
        if kind == 'session':
            logger.debug("Session channel accepted.")
            return paramiko.OPEN_SUCCEEDED
        logger.debug("Session channel rejected.")
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        logger.debug(f"PTY request received. Terminal: {term}")
        return True

    def check_channel_shell_request(self, channel):
        logger.debug("Shell request received.")
        self.event.set()
        return True

    def check_auth_password(self, username, password):
        logger.info(f"Password authentication requested for user: {username}")
        # The password is the signature
        signature = password
        logger.debug(f"Received signature: {signature}")

        if not signature.startswith('0x'):
            logger.warning("Invalid signature format.")
            return paramiko.AUTH_FAILED

        # Verify the signature against the AUTH_MESSAGE
        try:
            recovered_address = w3.eth.account.recover_message(
                encode_defunct(text=AUTH_MESSAGE),
                signature=signature
            ).lower()
            logger.info(f"Recovered Address: {recovered_address} from {self.client_address}")

            # Check if the recovered address is in the mapping
            user = WALLET_USER_MAP.get(recovered_address)
            if user:
                self.username = user
                logger.info(f"Authentication successful for user: {user} from {self.client_address}")
                return paramiko.AUTH_SUCCESSFUL
            else:
                logger.warning(f"Authentication failed: Unknown wallet address {recovered_address} from {self.client_address}")
                return paramiko.AUTH_FAILED

        except Exception as e:
            logger.error(f"Signature verification error from {self.client_address}: {e}")
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Disable public key authentication
        logger.debug("Public key authentication attempt detected and rejected.")
        return paramiko.AUTH_FAILED

    def check_auth_keyboard_interactive(self, username, submethods, details):
        # Disable keyboard-interactive authentication
        logger.debug("Keyboard-interactive authentication attempt detected and rejected.")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        logger.debug(f"Allowed authentication methods requested for user: {username}")
        return 'password'

    def get_username(self):
        return self.username

def parse_command(cmd_str):
    """Parse a command string, handling quoted arguments."""
    parts = []
    current_part = []
    in_quotes = False
    quote_char = None
    
    for char in cmd_str:
        if char in ['"', "'"]:
            if not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char:
                in_quotes = False
                quote_char = None
            else:
                current_part.append(char)
        elif char.isspace() and not in_quotes:
            if current_part:
                parts.append(''.join(current_part))
                current_part = []
        else:
            current_part.append(char)
    
    if current_part:
        parts.append(''.join(current_part))
    
    # Remove quotes from arguments
    parts = [p.strip('"\'') for p in parts]
    return parts

def handle_file_transfer(channel, command, username, client_address):
    """Handle file transfer commands."""
    try:
        parts = parse_command(command.strip())
        cmd = parts[0].lower()
        
        # Get current working directory
        current_dir = get_current_dir(username)
        user_home = get_user_home(username)
        logger.info(f"Current directory: {current_dir}")
        
        if cmd == 'cd':
            if len(parts) != 2:
                channel.send("Usage: cd <directory>\n".encode('utf-8'))
                return
                
            # Handle special paths
            if parts[1] == '~' or parts[1] == '/':
                new_path = get_user_home(username)
            else:
                # Handle path with possible .. components
                path_parts = parts[1].replace('\\', '/').split('/')
                current_path = os.path.abspath(current_dir)
                
                for part in path_parts:
                    if part == '..':
                        # Don't allow going above user's root home
                        if os.path.abspath(current_path) == os.path.abspath(get_user_home(username)):
                            channel.send("Error: Cannot go above home directory\n".encode('utf-8'))
                            return
                        current_path = os.path.dirname(current_path)
                    elif part == '.' or not part:
                        continue
                    else:
                        current_path = os.path.join(current_path, part)
                
                new_path = current_path
            
            # Ensure the path is within user's home directory
            if not os.path.abspath(new_path).startswith(os.path.abspath(get_user_home(username))):
                channel.send("Error: Cannot access directory outside home directory\n".encode('utf-8'))
                return
            
            # Check if directory exists
            if not os.path.isdir(new_path):
                channel.send(f"Error: Directory not found: {parts[1]}\n".encode('utf-8'))
                return
            
            # Update user's home directory
            os.environ[f'USER_HOME_{username}'] = new_path
            rel_path = os.path.relpath(new_path, get_user_home(username))
            display_path = '.' if rel_path == '.' else rel_path
            channel.send(f"Changed directory to: {display_path}\n".encode('utf-8'))
            
        elif cmd == 'mkdir':
            if len(parts) != 2:
                channel.send("Usage: mkdir <directory>\n".encode('utf-8'))
                return
                
            # Ensure the path is within user's home directory
            new_dir = os.path.abspath(os.path.join(current_dir, parts[1]))
            if not os.path.abspath(new_dir).startswith(os.path.abspath(user_home)):
                channel.send("Error: Cannot create directory outside home directory\n".encode('utf-8'))
                return
            
            try:
                os.makedirs(new_dir, exist_ok=True)
                channel.send(f"Created directory: {parts[1]}\n".encode('utf-8'))
            except Exception as e:
                channel.send(f"Error creating directory: {str(e)}\n".encode('utf-8'))
                return
        
        elif cmd == 'put':
            if len(parts) != 3:
                channel.send("Usage: put <local_path> <remote_path>\n".encode('utf-8'))
                return
                
            # Ensure the path is within user's home directory
            remote_path = os.path.join(current_dir, parts[2])
            if not os.path.abspath(remote_path).startswith(os.path.abspath(user_home)):
                channel.send("Error: Path must be within your home directory\n".encode('utf-8'))
                return
            
            # Create parent directory if needed
            os.makedirs(os.path.dirname(remote_path), exist_ok=True)
            logger.info(f"Ready to receive file at: {remote_path}")
            
            # Send ready signal
            channel.send("READY_TO_RECEIVE\n".encode('utf-8'))
            
            # Receive file size
            size_data = channel.recv(1024).decode('utf-8').strip()
            try:
                size = int(size_data)
                logger.info(f"File size: {size}")
            except ValueError:
                error_msg = f"Error: Invalid file size received: {size_data}\n"
                channel.send(error_msg.encode('utf-8'))
                logger.error(error_msg.strip())
                return
            
            # Send acknowledgment
            channel.send("OK\n".encode('utf-8'))
            
            # Receive and write file content
            with open(remote_path, 'wb') as f:
                remaining = size
                while remaining > 0:
                    chunk = channel.recv(min(remaining, 32768))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
                    # Send progress acknowledgment
                    channel.send(str(len(chunk)).encode('utf-8') + b'\n')
            
            if remaining == 0:
                channel.send("File received successfully.\n".encode('utf-8'))
                logger.info(f"File received successfully at {remote_path}")
            else:
                channel.send("Error: File transfer incomplete.\n".encode('utf-8'))
                logger.error("File transfer incomplete")
                
        elif cmd == 'get':
            if len(parts) < 2:
                channel.send("Usage: get <remote_path> [--zip|--tar|--sequential]\n".encode('utf-8'))
                return
                
            remote_path = os.path.join(current_dir, parts[1])
            if not os.path.abspath(remote_path).startswith(os.path.abspath(user_home)):
                channel.send("Error: Path must be within your home directory\n".encode('utf-8'))
                return
                
            if not os.path.exists(remote_path):
                channel.send(f"Error: Path not found: {parts[1]}\n".encode('utf-8'))
                return
                
            # Determine transfer mode
            mode = '--sequential'  # default mode
            if len(parts) > 2:
                mode = parts[2].lower()
                
            if os.path.isfile(remote_path):
                if mode in ['--zip', '--tar']:
                    # Handle single file archive
                    archive_format = 'zip' if mode == '--zip' else 'tar.gz'
                    temp_archive = os.path.join(user_home, f"{os.path.basename(remote_path)}.{archive_format}")
                    try:
                        if mode == '--zip':
                            with zipfile.ZipFile(temp_archive, 'w', zipfile.ZIP_DEFLATED) as zf:
                                arcname = os.path.basename(remote_path)
                                zf.write(remote_path, arcname)
                        else:
                            with tarfile.open(temp_archive, 'w:gz') as tar:
                                arcname = os.path.basename(remote_path)
                                tar.add(remote_path, arcname=arcname)
                        
                        # Send archive type and size
                        file_size = os.path.getsize(temp_archive)
                        channel.send(f"ARCHIVE\n{archive_format}\n{file_size}\n".encode('utf-8'))
                        
                        # Wait for client ready signal
                        ready = channel.recv(1024).decode('utf-8').strip()
                        if ready != "OK":
                            return
                            
                        # Send archive data
                        with open(temp_archive, 'rb') as f:
                            while True:
                                chunk = f.read(32768)
                                if not chunk:
                                    break
                                channel.send(chunk)
                                # Wait for progress acknowledgment
                                channel.recv(1024)
                                
                        channel.send("Transfer complete.\n".encode('utf-8'))
                    finally:
                        if os.path.exists(temp_archive):
                            os.remove(temp_archive)
                else:
                    # Sequential transfer for single file
                    channel.send(f"SEQUENTIAL\n1\n{os.path.getsize(remote_path)}\n".encode('utf-8'))
                    
                    # Wait for client ready signal
                    ready = channel.recv(1024).decode('utf-8').strip()
                    if ready != "OK":
                        return
                        
                    # Send file info
                    filename = os.path.basename(remote_path)
                    channel.send(f"{filename}\n{os.path.getsize(remote_path)}\n".encode('utf-8'))
                    
                    # Wait for client ready signal
                    ready = channel.recv(1024).decode('utf-8').strip()
                    if ready != "OK":
                        return
                    
                    # Send file data
                    with open(remote_path, 'rb') as f:
                        while True:
                            chunk = f.read(32768)
                            if not chunk:
                                break
                            channel.send(chunk)
                            # Wait for progress acknowledgment
                            channel.recv(1024)
                            
                    channel.send("Transfer complete.\n".encode('utf-8'))
            elif os.path.isdir(remote_path):
                if mode in ['--zip', '--tar']:
                    # Create archive file
                    archive_format = 'zip' if mode == '--zip' else 'tar.gz'
                    temp_archive = os.path.join(user_home, f"{os.path.basename(remote_path)}.{archive_format}")
                    try:
                        if mode == '--zip':
                            with zipfile.ZipFile(temp_archive, 'w', zipfile.ZIP_DEFLATED) as zf:
                                # Add all files maintaining directory structure
                                for root, _, files in os.walk(remote_path):
                                    for file in files:
                                        file_path = os.path.join(root, file)
                                        # Make paths relative to the directory itself
                                        rel_path = os.path.relpath(file_path, remote_path)
                                        zf.write(file_path, rel_path)
                        else:
                            with tarfile.open(temp_archive, 'w:gz') as tar:
                                for root, _, files in os.walk(remote_path):
                                    for file in files:
                                        file_path = os.path.join(root, file)
                                        rel_path = os.path.relpath(file_path, remote_path)
                                        tar.add(file_path, arcname=rel_path)
                                
                        # Send archive type, size, and directory flag
                        file_size = os.path.getsize(temp_archive)
                        channel.send(f"ARCHIVE\n{archive_format}\n{file_size}\nDIRECTORY\n".encode('utf-8'))
                        
                        # Wait for client ready signal
                        ready = channel.recv(1024).decode('utf-8').strip()
                        if ready != "OK":
                            return
                            
                        # Send archive data
                        with open(temp_archive, 'rb') as f:
                            while True:
                                chunk = f.read(32768)
                                if not chunk:
                                    break
                                channel.send(chunk)
                                # Wait for progress acknowledgment
                                channel.recv(1024)
                                
                        channel.send("Transfer complete.\n".encode('utf-8'))
                    finally:
                        if os.path.exists(temp_archive):
                            os.remove(temp_archive)
                            
                elif mode == '--sequential':
                    # Count files and total size
                    total_size = 0
                    files_to_send = []
                    for root, _, files in os.walk(remote_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Make paths relative to the directory itself
                            rel_path = os.path.relpath(file_path, remote_path)
                            size = os.path.getsize(file_path)
                            total_size += size
                            files_to_send.append((file_path, rel_path, size))
                    
                    # Send header with file count, total size, and directory flag
                    channel.send(f"SEQUENTIAL\n{len(files_to_send)}\n{total_size}\nDIRECTORY\n".encode('utf-8'))
                    
                    # Wait for client ready signal
                    ready = channel.recv(1024).decode('utf-8').strip()
                    if ready != "OK":
                        return
                    
                    # Send each file
                    for full_path, rel_path, size in files_to_send:
                        # Send file info
                        channel.send(f"{rel_path}\n{size}\n".encode('utf-8'))
                        
                        # Wait for client ready signal
                        ready = channel.recv(1024).decode('utf-8').strip()
                        if ready != "OK":
                            return
                        
                        # Send file data
                        with open(full_path, 'rb') as f:
                            while True:
                                chunk = f.read(32768)
                                if not chunk:
                                    break
                                channel.send(chunk)
                                # Wait for progress acknowledgment
                                channel.recv(1024)
                    
                    channel.send("Transfer complete.\n".encode('utf-8'))
                else:
                    channel.send("Error: Invalid transfer mode. Use --zip, --tar, or --sequential\n".encode('utf-8'))
                    
        elif cmd == 'ls':
            # List files in current directory or specified path
            if len(parts) == 1:
                path = current_dir  # Use current directory
            else:
                # If path is specified, it should be relative to current directory
                path = os.path.abspath(os.path.join(current_dir, parts[1]))
                
                # Ensure the path is within user's home directory
                if not os.path.abspath(path).startswith(os.path.abspath(user_home)):
                    channel.send("Error: Cannot access directory outside home directory\n".encode('utf-8'))
                    return
                
                if not os.path.exists(path):
                    channel.send(f"Error: Path not found: {parts[1]}\n".encode('utf-8'))
                    return
            
            items = []
            if os.path.isdir(path):
                # Get immediate directory contents only
                with os.scandir(path) as entries:
                    for entry in entries:
                        # Use basename for display
                        display_name = entry.name
                        stat = entry.stat()
                        if entry.is_dir():
                            items.append({
                                'name': display_name,
                                'type': 'dir',
                                'size': '-',
                                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            })
                        else:
                            size = stat.st_size
                            size_str = f'{size:,} B' if size < 1024 else \
                                     f'{size/1024:,.1f} KB' if size < 1024*1024 else \
                                     f'{size/1024/1024:,.1f} MB'
                            items.append({
                                'name': display_name,
                                'type': 'file',
                                'size': size_str,
                                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            })
                
                # Sort items by type (directories first) then name
                items.sort(key=lambda x: (x['type'] != 'dir', x['name'].lower()))
                
                # Find maximum lengths for formatting
                max_name = max(len(item['name']) for item in items) if items else 0
                max_size = max(len(item['size']) for item in items) if items else 0
                
                # Create formatted header and separator
                header = f"{'Type':<6} {'Name':<{max_name}} {'Size':>{max_size}} {'Modified':>19}"
                separator = f"{'-'*6} {'-'*max_name} {'-'*max_size} {'-'*19}"
                
                # Format each line
                lines = [header, separator]
                for item in items:
                    type_symbol = '<DIR>' if item['type'] == 'dir' else '     '
                    line = f"{type_symbol} {item['name']:<{max_name}} {item['size']:>{max_size}} {item['modified']:>19}"
                    lines.append(line)
                
                response = '\n'.join(lines) + '\n'
            else:
                # Single file
                stat = os.stat(path)
                size = stat.st_size
                size_str = f'{size:,} B' if size < 1024 else \
                         f'{size/1024:,.1f} KB' if size < 1024*1024 else \
                         f'{size/1024/1024:,.1f} MB'
                modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                header = f"{'Type':<6} {'Name':<20} {'Size':>10} {'Modified':>19}"
                separator = f"{'-'*6} {'-'*20} {'-'*10} {'-'*19}"
                line = f"{'     '} {os.path.basename(path):<20} {size_str:>10} {modified:>19}"
                response = '\n'.join([header, separator, line]) + '\n'
                
            channel.send(response.encode('utf-8'))
            
    except Exception as e:
        logger.error(f"File transfer error: {e}", exc_info=True)
        channel.send(f"Error: {str(e)}\n".encode('utf-8'))

def generate_qr_code(wallet_address):
    """Generate QR code for Etherscan wallet address link"""
    etherscan_url = f"https://etherscan.io/address/{wallet_address}"
    
    # Create QR code instance
    qr = QRCode()
    qr.add_data(etherscan_url)
    qr.make(fit=True)
    
    # Create string buffer to capture ASCII art
    buffer = StringIO()
    
    # Generate ASCII art
    qr.print_ascii(out=buffer)
    buffer.seek(0)
    
    return buffer.getvalue()

def generate_welcome_box(username, wallet_address, qr_code):
    """Generate a formatted welcome box with QR code"""
    # Center the QR code lines
    qr_lines = [line for line in qr_code.split('\n') if line.strip()]
    # Add exactly 20 spaces on each side and ensure total width is correct
    box_width = 78  # Total width inside borders
    qr_line_width = len(qr_lines[0])
    padding = (box_width - qr_line_width) // 2
    centered_qr = '\n'.join(f'║{" "*padding}{line}{" "*(box_width - qr_line_width - padding)}║' for line in qr_lines)
    
    # Calculate wallet line width
    wallet_prefix = "             Wallet: "
    url_prefix = "   https://etherscan.io/address/"
    remaining_space = box_width - len(wallet_prefix)
    
    box = f"""╔══════════════════════════════════════════════════════════════════════════════╗
║                      Welcome to Crypto SSH : {username:<30}  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
{centered_qr}
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                     Scan QR Code to View on Etherscan                        ║
║{wallet_prefix}{wallet_address:<{remaining_space}}║
║{url_prefix}{wallet_address:<{box_width - len(url_prefix)}}║
╚══════════════════════════════════════════════════════════════════════════════╝"""
    return box

def handle_shell(channel, username, wallet_address):
    """
    Handles an interactive shell session.
    """
    try:
        # Generate QR code
        qr_code = generate_qr_code(wallet_address)
        
        # Generate welcome box
        welcome_box = generate_welcome_box(username, wallet_address, qr_code)
        
        # Add command help for client display
        welcome = f"{welcome_box}\n\nType 'help' for available commands or 'exit' to close connection.\n\n"
        
        # Send welcome message in chunks
        send_all(channel, welcome)
        
        # Log welcome with formatted box on server side
        logger.info("Interactive shell session started.")
        logger.info("\n" + welcome_box)
        
        # Initialize command buffer
        buffer = ""
        
        while True:
            try:
                # Send shell prompt if buffer is empty
                if not buffer:
                    channel.send("shell> ".encode('utf-8'))
                
                # Receive data from client
                data = channel.recv(1024)
                if not data:
                    logger.info(f"No data received from {username}@{channel.getpeername()[0]}. Closing connection.")
                    break
                
                # Add to buffer and process complete commands
                buffer += data.decode('utf-8')
                
                # Process all complete commands in buffer
                while '\n' in buffer:
                    # Extract next command
                    command, buffer = buffer.split('\n', 1)
                    command = command.strip()
                    
                    if not command:
                        continue
                        
                    logger.info(f"Processing command from {username}@{channel.getpeername()[0]}: {command}")
                    
                    if command.lower() == 'exit':
                        channel.send("Goodbye!\r\n".encode('utf-8'))
                        logger.info(f"Exit command received from {username}@{channel.getpeername()[0]}. Closing connection.")
                        return
                    elif command.startswith('file'):
                        handle_file_transfer(channel, command[5:], username, channel.getpeername()[0])
                    else:
                        # Echo the command back
                        response = f"Unknown command: {command}\r\n"
                        channel.send(response.encode('utf-8'))
                        logger.debug(f"Sent response to {username}@{channel.getpeername()[0]}: {response.strip()}")
                    
            except socket.timeout:
                continue
                
    except Exception as e:
        logger.error(f"Exception in shell for {username}@{channel.getpeername()[0]}: {e}")
    finally:
        logger.info(f"Closing shell for {username}@{channel.getpeername()[0]}")
        channel.close()

def send_all(channel, data):
    """Send all data to channel in chunks"""
    chunk_size = 4096
    data_bytes = data.encode('utf-8')
    for i in range(0, len(data_bytes), chunk_size):
        chunk = data_bytes[i:i + chunk_size]
        channel.send(chunk)

def handle_client(client_socket, client_address):
    username = None
    transport = None
    try:
        logger.info(f"Incoming connection from {client_address[0]}:{client_address[1]}")
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        
        server = WalletAuthServer(client_address)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            logger.error(f"SSH negotiation failed: {e}")
            return
            
        # Wait for auth
        channel = transport.accept(20)
        if channel is None:
            logger.error("No channel.")
            return
            
        # Get authenticated username
        username = server.get_username()
        logger.info(f"User '{username}' authenticated from {client_address}")
        
        # Get wallet address from mapping
        wallet_address = None
        for address, user in WALLET_USER_MAP.items():
            if user == username:
                wallet_address = address
                break
        
        if wallet_address is None:
            logger.error(f"Wallet address not found for user {username}")
            return
        
        # Wait for shell request
        if not server.event.wait(5):
            logger.warning("No shell request received")
            channel.close()
            return
        
        # Start shell interaction
        handle_shell(channel, username, wallet_address)
        
    except Exception as e:
        logger.error(f"Exception handling client {client_address}: {e}")
    finally:
        if transport is not None:
            transport.close()
        if client_socket is not None:
            client_socket.close()
        if username:
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