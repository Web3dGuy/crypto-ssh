# client/ssh_wallet_client.py

import paramiko
import sys
import logging
import socket
from dotenv import load_dotenv
import os
from web3 import Web3, Account
from eth_account.messages import encode_defunct
import tqdm
import time
import zipfile
import shutil
import tarfile
import threading

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
USER_NAME = os.getenv('USERNAME', 'walletuser').upper()
if not WALLET_ADDRESS or not PRIVATE_KEY or not USER_NAME:
    logger.error("USERNAME, WALLET_ADDRESS, and PRIVATE_KEY must be set in .env")
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

def wait_for_response(channel, expected=None):
    """Wait for a response from the server and validate it."""
    try:
        response = channel.recv(1024).decode('utf-8')
        if not response:
            return None
        return response.strip()
    except socket.timeout:
        return None

def upload_file(channel, local_path, remote_path):
    """Upload a file to the remote server."""
    try:
        # Normalize paths for cross-platform compatibility
        local_path = os.path.normpath(local_path)
        remote_path = remote_path.replace('\\', '/')  # Always use forward slashes for remote paths
        
        # Send the put command
        command = f'file put "{local_path}" "{remote_path}"'
        logger.info(f"Uploading file: {local_path}")
        logger.debug(f"Sending command: {command}")
        channel.send(command.encode('utf-8') + b'\n')
        
        # Wait for server ready signal
        response = wait_for_response(channel, "READY_TO_RECEIVE")
        if not response:
            logger.error(f"Server not ready to receive file")
            return False
            
        # Get file size and send it
        file_size = os.path.getsize(local_path)
        channel.send(str(file_size).encode('utf-8') + b'\n')
        
        # Wait for acknowledgment
        response = wait_for_response(channel, "OK")
        if not response:
            logger.error(f"Server did not acknowledge file size")
            return False
            
        # Send file contents
        with open(local_path, 'rb') as f:
            bytes_sent = 0
            with tqdm.tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Uploading {os.path.basename(local_path)}") as pbar:
                while bytes_sent < file_size:
                    chunk = f.read(32768)
                    if not chunk:
                        break
                    channel.send(chunk)
                    bytes_sent += len(chunk)
                    
                    # Wait for chunk acknowledgment
                    ack = wait_for_response(channel)
                    if not ack or not ack.isdigit():
                        logger.error(f"Invalid chunk acknowledgment: {ack}")
                        return False
                    pbar.update(int(ack))
                
        # Get final confirmation
        final_response = wait_for_response(channel)
        if not final_response or "successfully" not in final_response.lower():
            logger.error(f"Failed to upload: {local_path}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Failed to upload: {local_path}", exc_info=True)
        return False

def upload_directory(channel, local_dir, remote_dir):
    """Upload a directory and its contents to the remote server."""
    try:
        # Normalize paths for cross-platform compatibility
        local_dir = os.path.normpath(local_dir)
        remote_dir = remote_dir.replace('\\', '/')  # Always use forward slashes for remote paths
        
        logger.info(f"Uploading directory: {local_dir}")
        
        # Create remote directory first
        mkdir_cmd = f'file mkdir "{remote_dir}"'
        logger.debug(f"Sending command: {mkdir_cmd}")
        channel.send(mkdir_cmd.encode('utf-8') + b'\n')
        
        # Wait for mkdir response
        response = wait_for_response(channel)
        if not response or not response.startswith("Directory created"):
            logger.error(f"Failed to create directory: {remote_dir}")
            return False
        logger.debug(f"Mkdir response: {response}")
            
        success = True
        # Walk through directory and upload files
        for root, _, files in os.walk(local_dir):
            for file in files:
                local_path = os.path.join(root, file)
                rel_path = os.path.relpath(local_path, local_dir)
                remote_path = f"{remote_dir}/{rel_path}".replace("\\", "/")
                
                logger.info(f"Processing item: {local_path} -> {remote_path}")
                if not upload_file(channel, local_path, remote_path):
                    success = False
                    
        return success
        
    except Exception as e:
        logger.error(f"Failed to upload directory: {local_dir}", exc_info=True)
        return False

def download_file(channel, remote_path, local_path, mode='--sequential'):
    """Download a file from the remote server."""
    try:
        # Normalize paths
        remote_path = remote_path.replace('\\', '/')
        local_path = local_path.replace('\\', '/')
        
        # Determine if we're downloading to a directory
        is_dir_target = local_path.endswith('/') or local_path.endswith('\\') or os.path.isdir(local_path)
        
        # If local_path is a directory, append the base name of remote path
        if is_dir_target:
            # Create directory if it doesn't exist
            os.makedirs(local_path, exist_ok=True)
            # Append the base name of the remote file
            local_path = os.path.join(local_path, os.path.basename(remote_path))
        else:
            # Create parent directory if needed
            parent_dir = os.path.dirname(os.path.abspath(local_path))
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            
        # Send get command - format properly
        command = f'file get "{remote_path}" {mode}'
        logger.debug(f"Sending command: {command}")
        channel.send(command.encode('utf-8') + b'\n')
        
        # Get response header with timeout
        channel.settimeout(5.0)  # Set timeout for initial response
        try:
            response = channel.recv(1024).decode('utf-8').strip()
            logger.debug(f"Initial response: {response}")
            if not response:
                logger.error("No response from server")
                return False
                
            # Skip shell prompts in response
            while response == 'shell>':
                response = channel.recv(1024).decode('utf-8').strip()
                logger.debug(f"Initial response (after skip): {response}")
                
        except socket.timeout:
            logger.error("Timeout waiting for server response")
            return False
            
        # Parse response header
        parts = response.split('\n')
        if len(parts) < 1:
            logger.error("Invalid response header")
            return False
            
        transfer_type = parts[0]
        
        if transfer_type == 'SEQUENTIAL':
            num_files = int(parts[1])
            total_size = int(parts[2])
            is_directory = len(parts) > 3 and parts[3] == 'DIRECTORY'
            
            # Send ready signal
            channel.send("OK\n".encode('utf-8'))
            
            # Create base directory if this is a directory download
            if is_directory:
                os.makedirs(local_path, exist_ok=True)
            else:
                # Create parent directory for single file
                parent_dir = os.path.dirname(os.path.abspath(local_path))
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
            
            # Process each file
            for _ in range(num_files):
                # Get file info
                file_info = channel.recv(1024).decode('utf-8').strip()
                file_parts = file_info.split('\n')
                if len(file_parts) != 2:
                    logger.error(f"Invalid file info: {file_info}")
                    return False
                    
                rel_path = file_parts[0]
                file_size = int(file_parts[1])
                
                # Send ready signal
                channel.send("OK\n".encode('utf-8'))
                
                # Determine target path
                if is_directory:
                    # For directories, maintain structure under local_path
                    target_path = os.path.join(local_path, rel_path)
                else:
                    # For single files, use local_path as the file path
                    target_path = local_path
                
                # Create parent directories
                parent_dir = os.path.dirname(os.path.abspath(target_path))
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
                
                logger.debug(f"Downloading to: {target_path}")
                bytes_received = 0
                with open(target_path, 'wb') as f:
                    with tqdm.tqdm(total=file_size, unit='B', unit_scale=True, desc="Total Progress") as pbar:
                        while bytes_received < file_size:
                            chunk = channel.recv(min(32768, file_size - bytes_received))
                            if not chunk:
                                logger.error("Connection closed during transfer")
                                return False
                            f.write(chunk)
                            bytes_received += len(chunk)
                            pbar.update(len(chunk))
                            # Send progress acknowledgment
                            channel.send(str(len(chunk)).encode('utf-8') + b'\n')
                            
            # Wait for completion message
            completion = channel.recv(1024).decode('utf-8').strip()
            logger.debug(f"Completion message: {completion}")
            if "complete" not in completion.lower():
                logger.error(f"Transfer failed: {completion}")
                return False
                
            logger.info("Sequential transfer completed")
            return True
            
        elif transfer_type == 'ARCHIVE':
            archive_format = parts[1]
            file_size = int(parts[2])
            is_directory = len(parts) > 3 and parts[3] == 'DIRECTORY'
            
            # Create temp directory for download
            temp_dir = os.path.join(os.path.dirname(os.path.abspath(local_path)), '.temp')
            os.makedirs(temp_dir, exist_ok=True)
            temp_archive = os.path.join(temp_dir, f"temp.{archive_format}")
            
            try:
                # Send ready signal
                channel.send("OK\n".encode('utf-8'))
                logger.debug("Sent OK signal")
                
                # Download archive
                with open(temp_archive, 'wb') as f:
                    bytes_received = 0
                    with tqdm.tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Downloading archive") as pbar:
                        while bytes_received < file_size:
                            chunk = channel.recv(min(32768, file_size - bytes_received))
                            if not chunk:
                                logger.error("Connection closed during transfer")
                                return False
                            f.write(chunk)
                            bytes_received += len(chunk)
                            pbar.update(len(chunk))
                            channel.send(str(len(chunk)).encode('utf-8') + b'\n')
                
                # Extract archive
                if archive_format == 'zip':
                    with zipfile.ZipFile(temp_archive, 'r') as zf:
                        if is_directory:
                            # Create target directory if it doesn't exist
                            os.makedirs(local_path, exist_ok=True)
                            zf.extractall(local_path)
                        else:
                            # Single file - extract directly
                            first_file = next(name for name in zf.namelist())
                            with zf.open(first_file) as source, open(local_path, 'wb') as target:
                                shutil.copyfileobj(source, target)
                else:
                    with tarfile.open(temp_archive, 'r:gz') as tar:
                        if is_directory:
                            # Directory download with path traversal protection
                            os.makedirs(local_path, exist_ok=True)
                            def is_within_directory(directory, target):
                                abs_directory = os.path.abspath(directory)
                                abs_target = os.path.abspath(target)
                                prefix = os.path.commonprefix([abs_directory, abs_target])
                                return prefix == abs_directory
                            
                            def safe_extract(tar, path):
                                for member in tar.getmembers():
                                    member_path = os.path.join(path, member.name)
                                    if not is_within_directory(path, member_path):
                                        logger.error(f"Attempted path traversal in tar file: {member.name}")
                                        continue
                                    tar.extract(member, path)
                            
                            safe_extract(tar, local_path)
                        else:
                            # Single file - extract directly
                            first_file = next(member for member in tar.getmembers())
                            with tar.extractfile(first_file) as source, open(local_path, 'wb') as target:
                                shutil.copyfileobj(source, target)
                
                logger.info("Extraction completed")
                return True
                
            finally:
                # Reset timeout
                channel.settimeout(None)
                # Clean up temp archive
                if os.path.exists(temp_archive):
                    os.remove(temp_archive)
                if os.path.exists(temp_dir) and not os.listdir(temp_dir):
                    os.rmdir(temp_dir)
                    
        else:
            logger.error(f"Unsupported transfer type: {transfer_type}")
            return False
            
    except Exception as e:
        logger.error(f"Download error: {e}", exc_info=True)
        return False
    finally:
        # Reset timeout
        channel.settimeout(None)

def handle_file_command(channel, command):
    """Handle file-related commands."""
    try:
        parts = command.split()
        if len(parts) < 2:
            print("""Available file commands:
- file ls [path]                    : List files in remote directory
- file cd <path>                    : Change current directory
- file mkdir <path>                 : Create a new directory
- file put <local> <remote>         : Upload local file/directory to remote path
- file get <remote> [local]         : Download remote file/directory to local path
                                     If local path is not specified, uses remote name
                                     For directories, you can choose to download as:
                                     - Individual files (default)
                                     - ZIP archive (Windows)
                                     - TAR.GZ archive (Linux/Mac)""")
            return
            
        cmd = parts[1].lower()
        
        if cmd == 'cd':
            if len(parts) != 3:
                print("Usage: file cd <path>")
                print("  Changes the current working directory on the remote server")
                print("  Examples:")
                print("    file cd folder")
                print("    file cd ..")
                print("    file cd ~")
                return
                
            channel.send(f"file cd {parts[2]}\n".encode('utf-8'))
            response = wait_for_response(channel)
            if response:
                print(response)
                
        elif cmd == 'mkdir':
            if len(parts) != 3:
                print("Usage: file mkdir <path>")
                print("  Creates a new directory on the remote server")
                print("  Examples:")
                print("    file mkdir newfolder")
                print("    file mkdir path/to/newfolder")
                return
                
            channel.send(f"file mkdir {parts[2]}\n".encode('utf-8'))
            response = wait_for_response(channel)
            if response:
                print(response)
                
        elif cmd == 'put':
            if len(parts) < 4:
                print("Usage: file put <local_path> <remote_path>")
                print("  Uploads a file or directory to the remote server")
                print("  Examples:")
                print("    file put myfile.txt remote/myfile.txt")
                print("    file put localdir remotedir")
                return
                
            local_path = parts[2]
            if not os.path.exists(local_path):
                print(f"Local path not found: {local_path}")
                return
                
            # Normalize remote path to use forward slashes
            remote_path = parts[3].replace('\\', '/')  # Always use forward slashes for remote paths
            
            if os.path.isfile(local_path):
                if not upload_file(channel, local_path, remote_path):
                    print("Transfer failed")
                else:
                    print("Transfer completed successfully")
            elif os.path.isdir(local_path):
                if not upload_directory(channel, local_path, remote_path):
                    print("Transfer failed")
                else:
                    print("Transfer completed successfully")
            else:
                print(f"Path not found: {local_path}")
                
        elif cmd == 'get':
            if len(parts) < 3:
                print("Usage: file get <remote_path> [local_path]")
                print("  Downloads a file or directory from the remote server")
                print("  If local path is not specified, uses the remote name")
                print("  Examples:")
                print("    file get remote/myfile.txt")
                print("    file get remote/myfile.txt local/myfile.txt")
                print("    file get remotedir")
                print("    file get remotedir localdir")
                return
                
            remote_path = parts[2]
            local_path = parts[3] if len(parts) > 3 else os.path.basename(remote_path)
            
            # Ask about archive format
            use_archive = input("Download as archive? [y/N] ").lower().startswith('y')
            if use_archive:
                # Use ZIP for Windows, tar.gz for others
                archive_type = '--zip' if os.name == 'nt' else '--tar'
            else:
                archive_type = '--sequential'
                
            # Format command properly - don't include mode in quotes
            if not download_file(channel, remote_path, local_path, archive_type):
                print("Transfer failed")
            else:
                print("Transfer completed successfully")
                
        elif cmd == 'ls':
            command = "file ls" if len(parts) < 3 else f"file ls {parts[2]}"
            channel.send(command.encode('utf-8') + b'\n')
            response = wait_for_response(channel)
            if response:
                print(response)
            
    except Exception as e:
        logger.error(f"Command error: {e}", exc_info=True)
        print("Command failed")

def receive_all(channel, timeout=1.0):
    """Receive all data from channel until timeout"""
    result = []
    channel.settimeout(timeout)
    try:
        while True:
            chunk = channel.recv(4096)
            if not chunk:
                break
            result.append(chunk)
    except socket.timeout:
        pass
    finally:
        channel.settimeout(None)
    return b''.join(result)

def interactive_shell(channel):
    """
    Provide an interactive shell session.
    """
    try:
        # Receive initial welcome message with potential QR code
        welcome_data = receive_all(channel)
        try:
            print(welcome_data.decode('utf-8'), end='')
        except UnicodeDecodeError as e:
            logger.error(f"Error decoding welcome message: {e}")
            print(welcome_data.decode('utf-8', errors='replace'), end='')
        
        while True:
            try:
                # Get user input
                command = input("")
                
                if not command:
                    channel.send('\n')
                    continue
                    
                if command.lower() == 'exit':
                    logger.info("Exit command received. Closing interactive shell.")
                    channel.send(command + '\n')
                    break
                    
                elif command.lower().startswith('file '):
                    channel.in_file_operation = True
                    handle_file_command(channel, command)
                    channel.in_file_operation = False
                    # Clear any pending data
                    channel.settimeout(0.1)
                    try:
                        while channel.recv(1024):
                            pass
                    except socket.timeout:
                        pass
                    channel.settimeout(None)
                else:
                    channel.send(command + '\n')
                    
                    # Wait for response
                    channel.settimeout(0.1)
                    try:
                        while True:
                            chunk = channel.recv(1024)
                            if not chunk:
                                break
                            response = chunk.decode('utf-8')
                            if 'shell> ' in response:
                                response = response.replace('shell> ', '')
                            print(response, end='')
                    except socket.timeout:
                        pass
                    channel.settimeout(None)
                    
            except socket.timeout:
                continue
            except (EOFError, KeyboardInterrupt):
                break
                    
    except Exception as e:
        logger.error(f"Interactive shell error: {e}", exc_info=True)
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
            username=USER_NAME,  # The username should match the server's mapping
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
        logger.info("Interactive shell session started .")

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