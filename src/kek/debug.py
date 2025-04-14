import sys
from eth_abi import encode
import json

# Use relative imports
from .utils import hex_to_bytes
# from .parsing import format_json_to_solidity_struct # Need to format first
from .format import format_user_op_data # Updated import

# Hardcode EntryPoint v0.7 address here
ENTRY_POINT_V07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"

def run_debug_command(args, user_op_intermediate_data):
    """Generates and prints the handleOps cast call command."""
    beneficiary = "0x0000000000000000000000000000000000000000" # Hardcoded zero address
    # -- Prepare UserOperation data for encoding -- 
    try:
        # Format the intermediate data using the updated function
        intermediate_json_str = json.dumps(user_op_intermediate_data)
        final_json = format_user_op_data(intermediate_json_str)
        user_op_dict = json.loads(final_json)
    except ValueError as e:
        print(f"Error formatting UserOperation data: {e}")
        sys.exit(1)
    except Exception as e: # Catch other potential errors
        print(f"Unexpected error during UserOperation formatting: {e}")
        sys.exit(1)

    try:
        user_op_tuple = (
            user_op_dict['sender'],
            int(user_op_dict['nonce']),
            hex_to_bytes(user_op_dict['initCode']),
            hex_to_bytes(user_op_dict['callData']),
            hex_to_bytes(user_op_dict['accountGasLimits']),
            int(user_op_dict['preVerificationGas']),
            hex_to_bytes(user_op_dict['gasFees']),
            hex_to_bytes(user_op_dict['paymasterAndData']),
            hex_to_bytes(user_op_dict['signature'])
        )
    except KeyError as e:
         print(f"Error: Missing key '{e}' in formatted UserOperation JSON needed for ABI encoding.")
         sys.exit(1)
    except (ValueError, TypeError) as e:
         print(f"Error converting UserOperation fields for ABI encoding: {e}")
         sys.exit(1)
         
    ops_array = [user_op_tuple]

    user_op_abi_type = '(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)'
    handle_ops_input_types = [f'{user_op_abi_type}[]', 'address']
    
    # -- ABI Encode handleOps call --
    try:
        encoded_call_data = encode(
            handle_ops_input_types,
            [ops_array, beneficiary] # Use hardcoded zero address
        )
    except Exception as e:
        print(f"\nError ABI encoding handleOps data: {e}")
        sys.exit(1)

    handle_ops_selector = "0x765e827f" # v0.7 selector
    full_calldata = handle_ops_selector + encoded_call_data.hex()
    
    # -- Construct cast command list and string --
    cast_command_list = [
        "cast", "call", 
        ENTRY_POINT_V07, 
        full_calldata, 
        "--rpc-url", args.rpc_url, 
        "--trace"
    ]
    cast_command_string = ' '.join(cast_command_list) # For printing

    # -- Print cast command --
    print(cast_command_string)
