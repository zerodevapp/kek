import json
import subprocess
import sys
from eth_abi import encode

# Use relative imports
# from utils import hex_to_bytes
# from parsing import format_json_to_solidity_struct
from .utils import hex_to_bytes
from .parsing import format_json_to_solidity_struct # Need to format first

# Hardcode EntryPoint v0.7 address here
ENTRY_POINT_V07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"

def run_debug_command(args, user_op_intermediate_data):
    """Generates and optionally executes the handleOps cast call command."""
    beneficiary = "0x0000000000000000000000000000000000000000" # Hardcoded zero address

    # -- Prepare UserOperation data for encoding -- 
    try:
        # Need to format the intermediate data first
        intermediate_json_str = json.dumps(user_op_intermediate_data) # Convert dict back to string if needed
        final_json = format_json_to_solidity_struct(intermediate_json_str)
        user_op_dict = json.loads(final_json)
    except Exception as e:
        print(f"Error formatting UserOperation data: {e}")
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

    if args.run:
        # -- Execute cast command --
        print(f"\nExecuting command: {cast_command_string}")
        try:
            result = subprocess.run(
                cast_command_list, 
                capture_output=True, text=True, check=False
            )
            
            print("\n--- Command Output --- ")
            if result.stdout:
                print("[STDOUT]")
                print(result.stdout.strip())
            if result.stderr:
                print("[STDERR]")
                print(result.stderr.strip())
            
            if result.returncode != 0:
                print(f"\nWarning: Command exited with non-zero status code: {result.returncode}")

        except FileNotFoundError:
             print("\nError: 'cast' command not found. Make sure foundry is installed and in your PATH.")
             sys.exit(1)
        except Exception as sub_error:
             print(f"\nError executing command: {sub_error}")
             sys.exit(1)
    else:
         # -- Print cast command --
        print(cast_command_string) 