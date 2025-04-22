from .constants import PIMLICO_ESTIMATION_ADDRESS, ENTRY_POINT_V07
from eth_abi import encode, decode
import sys
import json
from web3 import Web3

from .format import format_user_op_data
from .utils import hex_to_bytes, decode_simulate_lastOp_error, decode_simulate_lastOp_result, to_cast_trace_command

# Correct function selectors
SIMULATE_ENTRY_POINT_SELECTOR = "0xc18f5226"
SIMULATE_HANDLE_OP_LAST_SELECTOR = "0x263934db"  # simulateHandleOpLast selector

SIMULATE_TARGET = "0xf384fddcaf70336dca46404d809153a0029a0253"
def encode_simulate_command(args, user_op_intermediate_data):
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

    simulation_result = {}
    # simulate the user op last
    try:
        simulation_result.execution_result = simulate_user_op_last(args.rpc_url, user_op_tuple)
    except FailedUserOp as e:
        print(e)
        cast_command_list = e.command()
        cast_command_list.append("--rpc-url")
        cast_command_list.append(args.rpc_url)
        cast_command_string = ' '.join(cast_command_list)
        print(cast_command_string)
        sys.exit(1)

    # validation_result = decode( ['((uint256,uint256,uint256,uint256,bytes),(uint256,uint256),(uint256,uint256),(uint256,uint256),(address,(uint256,uint256)))'], decoded_results[1])
    # print(validation_result)
    # -- Construct cast command list and string --
    # cast_command_list = [
    #     "cast", "call", 
    #     PIMLICO_ESTIMATION_ADDRESS, 
    #     simulate_calldata, 
    #     "--rpc-url", args.rpc_url,
    #     "--trace"
    # ]
    # cast_command_string = ' '.join(cast_command_list)  # For printing

    # print(cast_command_string)

def simulate_user_op_last(rpc_url,user_op_tuple) -> object:
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
    # check simulation return data
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    abi = """
[
    {
        "inputs": [{"internalType": "address", "name": "entryPoint", "type": "address"}, {"internalType": "bytes[]", "name": "userOps", "type": "bytes[]"}],
        "name": "simulateEntryPoint",
        "outputs": [{"internalType": "bytes[]", "name": "results", "type": "bytes[]"}],
        "stateMutability": "view",
        "type": "function"
    }
    ]
    """

    """
    struct ReturnInfo {
        uint256 preOpGas;
        uint256 prefund;
        uint256 accountValidationData;
        uint256 paymasterValidationData;
        bytes paymasterContext;
    }

    struct AggregatorStakeInfo {
        address aggregator;
        StakeInfo stakeInfo;
    }

    struct StakeInfo {
        uint256 stake;
        uint256 unstakeDelaySec;
    }

    struct ValidationResult {
        ReturnInfo returnInfo;
        StakeInfo senderInfo;
        StakeInfo factoryInfo;
        StakeInfo paymasterInfo;
        AggregatorStakeInfo aggregatorInfo;
    }
    """

    """
    struct ExecutionResult {
        uint256 preOpGas;
        uint256 paid;
        uint256 accountValidationData;
        uint256 paymasterValidationData;
        uint256 paymasterVerificationGasLimit;
        uint256 paymasterPostOpGasLimit;
        bool targetSuccess;
        bytes targetResult;
    }
    """
    contract = w3.eth.contract(address=Web3.to_checksum_address(PIMLICO_ESTIMATION_ADDRESS), abi=abi)
    results = contract.functions.simulateEntryPoint(ENTRY_POINT_V07, [bytes.fromhex(simulate_last_data[2:])]).call()
    decoded_results = decode( ['bool', 'bytes'], results[0][4:])
    # if simulation was successful, print the execution result
    if decoded_results[0]:
        details = decode_simulate_lastOp_result(decoded_results[1])
        return details
    else:
        raise FailedUserOp(decode_simulate_lastOp_error(decoded_results[1]), simulate_calldata)


class FailedUserOp(Exception):
    def __init__(self, message, debugCallData):
        self.message = message
        self.debugCallData = debugCallData
        super().__init__(self.message)

    def __str__(self):
        return f"Failed UserOp : {self.message[:4]}"
    
    def command(self):
        return to_cast_trace_command(SIMULATE_TARGET, self.debugCallData)