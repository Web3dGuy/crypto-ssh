# verify_wallet.py
from web3 import Web3, Account

private_key = "0x..."
account = Account.from_key(private_key)
print(f"Wallet Address: {account.address.lower()}")