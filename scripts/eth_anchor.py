import sys
import os
import json
from web3 import Web3

def main():
    if len(sys.argv) != 2:
        print("Usage: python eth_anchor.py <root_hash>")
        sys.exit(1)

    root_hash = sys.argv[1]
    if not root_hash.startswith("0x"):
        root_hash = "0x" + root_hash

    rpc_url = os.environ.get("CRYPTVAULT_ETH_RPC_URL")
    private_key = os.environ.get("CRYPTVAULT_ETH_PRIVATE_KEY")
    contract_address = os.environ.get("CRYPTVAULT_ETH_CONTRACT")

    if not rpc_url or not private_key or not contract_address:
        print("Error: Missing Ethereum environment variables.")
        print("Please set CRYPTVAULT_ETH_RPC_URL, CRYPTVAULT_ETH_PRIVATE_KEY, and CRYPTVAULT_ETH_CONTRACT.")
        sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("Error: Could not connect to Ethereum RPC.")
        sys.exit(1)

    account = w3.eth.account.from_key(private_key)

    abi = [
        {
            "inputs": [{"internalType": "bytes32", "name": "rootHash", "type": "bytes32"}],
            "name": "anchorChain",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]

    contract = w3.eth.contract(address=contract_address, abi=abi)

    nonce = w3.eth.get_transaction_count(account.address)
    
    # ensure it's a 32-byte hex string
    if len(root_hash) != 66:
        print("Error: Root hash must be 32 bytes (64 hex characters).")
        sys.exit(1)

    tx = contract.functions.anchorChain(bytes.fromhex(root_hash[2:])).build_transaction({
        'chainId': w3.eth.chain_id,
        'gas': 2000000,
        'maxFeePerGas': w3.to_wei('2', 'gwei'),
        'maxPriorityFeePerGas': w3.to_wei('1', 'gwei'),
        'nonce': nonce,
    })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f"Transaction broadcasted: {w3.to_hex(tx_hash)}")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
