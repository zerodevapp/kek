# src/kek/check.py
from web3 import Web3, HTTPProvider
from .constants import ZERO_ADDRESS

def get_executor_status_on_chain(kernel_address: str, expected_executor_address: str, rpc_url: str) -> bool:
    """Performs the on-chain check for the executor and returns a results dictionary."""
    results = {
        "success": False,
        "message": "",
        "details": {
            "kernel_address": kernel_address,
            "expected_executor_address": expected_executor_address,
            "rpc_url": rpc_url,
            "function_called": None,
            "actual_executor_on_chain": None,
            "match": None
        }
    }

    try:
        if not Web3.is_address(kernel_address):
            results["message"] = f"Error: Invalid KERNEL_ADDRESS: {kernel_address}"
            return results
        if not Web3.is_address(expected_executor_address):
            results["message"] = f"Error: Invalid EXECUTOR_ADDRESS: {expected_executor_address}"
            return results

        w3 = Web3(HTTPProvider(rpc_url))
        if not w3.is_connected():
            results["message"] = f"Error: Could not connect to RPC URL: {rpc_url}"
            return results

        # Based on your feedback, specifically target executorConfig(address)
        # Assuming the address argument to query the default/primary executor is the zero address.
        func_name = "executorConfig"
        # If this address argument is different, please let me know.
        address_arg_for_query = "0x0000000000000000000000000000000000000000" 

        executor_config_abi = [{
            "inputs": [{"internalType": "address", "name": "queryAddress", "type": "address"}],
            "name": func_name,
            "outputs": [{"internalType": "address", "name": "configuredExecutor", "type": "address"}],
            "stateMutability": "view",
            "type": "function"
        }]
        
        checksum_kernel_address = Web3.to_checksum_address(kernel_address)
        contract = w3.eth.contract(address=checksum_kernel_address, abi=executor_config_abi)
        
        actual_executor = contract.functions.executorConfig(address_arg_for_query).call()
        return actual_executor != ZERO_ADDRESS
    except Exception as e:
        results["message"] = f"An unexpected error occurred: {str(e)}"
        # Optionally include traceback for debugging if this function is called in a context where it can be logged
        # results["details"]["traceback"] = traceback.format_exc()
        return results 