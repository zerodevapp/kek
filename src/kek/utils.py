from eth_abi import decode
def hex_to_bytes(hex_string: str) -> bytes:
    """Converts a hex string (with or without 0x prefix) to bytes."""
    if not isinstance(hex_string, str):
         raise TypeError(f"Input must be a string, got {type(hex_string)}")
    if hex_string.startswith('0x'):
        # Handle empty bytes case
        if len(hex_string) == 2:
            return b''
        return bytes.fromhex(hex_string[2:])
    # Handle empty bytes case for non-prefixed string
    if not hex_string:
        return b''
    try:
        return bytes.fromhex(hex_string)
    except ValueError as e:
        raise ValueError(f"Invalid hex string for hex_to_bytes: '{hex_string[:20]}...'") from e 

def to_cast_trace_command(target_address, call_data):
    return ["cast", "call", target_address, call_data, "--trace"]

def decode_simulate_lastOp_error(error_bytes: bytes) -> str:
    """Decodes an error bytes into a string."""
    # FailedOp(uint256,string) == 0x220266b6
    # 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001a4141323520696e76616c6964206163636f756e74206e6f6e6365000000000000
    if error_bytes.hex().startswith("220266b6"):
        return decode(['uint256', 'string'], error_bytes[4:])[1]
    else:
        return "Unknown error"
    
def decode_simulate_lastOp_result(result_bytes: bytes) -> str:
    """Decodes a result bytes into a string."""
    decoded = decode(['(uint256,uint256,uint256,uint256,uint256,uint256,bool,bytes)'], result_bytes)
    # formatted execution result
    formatted_execution_result = {
        "preOpGas": decoded[0][0],
        "paid": decoded[0][1],
        "accountValidationData": decoded[0][2],
        "paymasterValidationData": decoded[0][3],
        "paymasterVerificationGasLimit": decoded[0][4],
        "paymasterPostOpGasLimit": decoded[0][5],
        "targetSuccess": decoded[0][6],
        "targetResult": decoded[0][7]
    }
    return formatted_execution_result   