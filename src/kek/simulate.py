from .constants import PIMLICO_ESTIMATION_ADDRESS, ENTRY_POINT_V07
from eth_abi import encode
import sys
import json

from .format import format_user_op_data
from .utils import hex_to_bytes

# Correct function selectors
SIMULATE_ENTRY_POINT_SELECTOR = "0xc18f5226"
SIMULATE_HANDLE_OP_LAST_SELECTOR = "0x263934db"  # simulateHandleOpLast selector

SIMULATE_TARGET = "0xf384fddcaf70336dca46404d809153a0029a0253"
def run_simulate_command(args, user_op_intermediate_data):
    """Generate a command to simulate a UserOperation using Pimlico's estimation contract."""
    
    # -- Prepare UserOperation data for encoding -- 
    try:
        # 1. Format the intermediate data dictionary into the final PackedUserOp JSON string
        final_json_string = format_user_op_data(user_op_intermediate_data)
        # 2. Load the final formatted JSON string into a dictionary for tuple creation
        user_op_dict = json.loads(final_json_string) 
    except ValueError as e:
        print(f"Error formatting/loading UserOperation data: {e}")
        sys.exit(1)
    except Exception as e: # Catch other potential errors
        print(f"Unexpected error during UserOperation formatting/loading: {e}")
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

    # --- Step 1: Encode the simulateHandleOpLast call ---
    user_op_abi_type = '(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)'
    
    try:
        # Encode simulateHandleOpLast with just the user ops
        encoded_simulate_last = encode(
            [f'{user_op_abi_type}[]'],  # Just the user ops array
            [ops_array]
        )
    except Exception as e:
        print(f"\nError encoding simulateHandleOpLast data: {e}")
        sys.exit(1)

    simulate_last_data = SIMULATE_HANDLE_OP_LAST_SELECTOR + encoded_simulate_last.hex()

    # --- Step 2: Encode the simulateEntryPoint call ---
    try:
        # Encode simulateEntryPoint with the entrypoint and simulateHandleOpLast calldata
        encoded_simulate = encode(
            ["address", "bytes[]"],
            [ENTRY_POINT_V07, [bytes.fromhex(simulate_last_data[2:])]]  # Remove 0x prefix
        )
    except Exception as e:
        print(f"\nError encoding simulateEntryPoint parameters: {e}")
        sys.exit(1)
        
    simulate_calldata = SIMULATE_ENTRY_POINT_SELECTOR + encoded_simulate.hex()
    
    # -- Construct cast command list and string --
    cast_command_list = [
        "cast", "call", 
        PIMLICO_ESTIMATION_ADDRESS, 
        simulate_calldata, 
        "--rpc-url", args.rpc_url,
        "--trace"
    ]
    cast_command_string = ' '.join(cast_command_list)  # For printing

    print(cast_command_string) 