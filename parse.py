import json
# Requires: pip install pysha3 eth-abi eth_keys
import sha3
from eth_abi import encode
import argparse # Added for command-line arguments
from eth_keys.exceptions import BadSignature
from eth_keys import keys # Added for signature recovery

def parse_text_to_json(text_data: str) -> str:
    """
    Parses the provided text format into a JSON string.

    Args:
        text_data: A string containing the key-value pairs.

    Returns:
        A JSON string representation of the parsed data.
    """
    parsed_data = {}
    lines = text_data.splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        colon_index = line.find(':')
        if colon_index == -1:
            # Skip lines without a colon
            continue

        key = line[:colon_index].strip()
        value = line[colon_index + 1:].strip()

        # Simple check to see if value might be numeric
        # This is basic; more robust parsing might be needed depending on requirements
        if value.isdigit():
            parsed_data[key] = int(value)
        elif value.startswith("0x") and all(c in '0123456789abcdefABCDEF' for c in value[2:]):
             # Keep hex strings as strings, including addresses
             parsed_data[key] = value
        else:
            # Handle potential float or keep as string
            try:
                # Attempt to convert to float if it contains a decimal or scientific notation
                if '.' in value or 'e' in value.lower():
                    parsed_data[key] = float(value)
                else:
                     # Keep as string if not clearly numeric/float
                    parsed_data[key] = value
            except ValueError:
                 # Keep as string if conversion fails
                parsed_data[key] = value


    return json.dumps(parsed_data, indent=2)


def format_json_to_solidity_struct(json_data: str) -> str:
    """
    Formats the JSON data into a JSON string with keys matching the
    Solidity PackedUserOperation struct fields.

    Args:
        json_data: A JSON string containing the user operation data.

    Returns:
        A JSON string representation of the PackedUserOperation data.
    """
    data = json.loads(json_data)

    # Helper to safely get data and provide default values
    def get_data(key, default=None):
        return data.get(key, default)

    # Helper to format uint256 to 0x-prefixed hex (64 chars)
    def format_uint256_hex(val):
        if isinstance(val, str) and val.isdigit():
            val = int(val)
        elif not isinstance(val, int):
            # Handle potentially very large numbers stored as strings
            try:
                val = int(val)
            except (ValueError, TypeError):
                 raise ValueError(f"Cannot convert {val} to integer for uint256 formatting")
        return f"0x{val:064x}"

    # Helper to format uint128 to hex (32 chars, no prefix)
    def format_uint128_hex_noprefix(val):
         if isinstance(val, str) and val.isdigit():
            val = int(val)
         elif not isinstance(val, int):
            try:
                val = int(val)
            except (ValueError, TypeError):
                 raise ValueError(f"Cannot convert {val} to integer for uint128 formatting")
         return f"{val:032x}"

    # Helper to convert gwei string (e.g., "0.1 gwei") to wei int
    def gwei_to_wei(gwei_str):
        if not isinstance(gwei_str, str):
            return 0 # Or raise error? Assume 0 if not string.
        try:
            # Extract numeric part
            num_part = gwei_str.split()[0]
            gwei_float = float(num_part)
            wei_int = int(gwei_float * 1e9)
            return wei_int
        except (ValueError, IndexError):
            raise ValueError(f"Could not parse gwei string: {gwei_str}")

    # --- Field Processing ---
    sender = get_data('sender', '0x' + '0' * 40)
    # Keep nonce as its original large integer string if possible, or format if int
    nonce_val = get_data('nonce', 0)
    if isinstance(nonce_val, str) and nonce_val.isdigit():
        nonce_str = nonce_val # Keep original large string
    else:
        nonce_str = str(nonce_val) # Convert int or other types to string

    callData = get_data('callData', '0x')
    preVerificationGas_val = get_data('preVerificationGas', 0)
    preVerificationGas_str = str(preVerificationGas_val) # Keep as string or int->string

    signature = get_data('signature', '0x')

    # initCode: factory + factoryData if factory exists
    factory = get_data('factory')
    factoryData = get_data('factoryData', '0x')
    if factory and factory != ('0x' + '0' * 40): # Check if factory is set and not zero address
        initCode = f"{factory}{factoryData.replace('0x', '')}"
    else:
        initCode = '0x'

    # accountGasLimits: verificationGasLimit (128) | callGasLimit (128)
    verificationGasLimit_val = get_data('verificationGasLimit', 0)
    callGasLimit_val = get_data('callGasLimit', 0)
    accountGasLimits = f"0x{format_uint128_hex_noprefix(verificationGasLimit_val)}{format_uint128_hex_noprefix(callGasLimit_val)}"

    # gasFees: maxFeePerGas (128) | maxPriorityFeePerGas (128)
    maxFeePerGas_wei = gwei_to_wei(get_data('maxFeePerGas', '0 gwei'))
    maxPriorityFeePerGas_wei = gwei_to_wei(get_data('maxPriorityFeePerGas', '0 gwei'))
    gasFees = f"0x{format_uint128_hex_noprefix(maxPriorityFeePerGas_wei)}{format_uint128_hex_noprefix(maxFeePerGas_wei)}"

    # paymasterAndData: paymaster + paymasterVerificationGasLimit (128) + paymasterPostOpGasLimit (128) + paymasterData
    paymaster = get_data('paymaster')
    paymasterData = get_data('paymasterData', '0x')
    if paymaster and paymaster != ('0x' + '0' * 40): # Check if paymaster is set and not zero address
        paymasterVerificationGasLimit_val = get_data('paymasterVerificationGasLimit', 0)
        paymasterPostOpGasLimit_val = get_data('paymasterPostOpGasLimit', 0)

        pm_ver_gas_hex = format_uint128_hex_noprefix(paymasterVerificationGasLimit_val)
        pm_post_gas_hex = format_uint128_hex_noprefix(paymasterPostOpGasLimit_val)

        paymasterAndData = f"{paymaster}{pm_ver_gas_hex}{pm_post_gas_hex}{paymasterData.replace('0x', '')}"
    else:
        paymasterAndData = '0x'


    # Construct the output dictionary
    output_dict = {
        "sender": sender,
        "nonce": nonce_str, # Keep as string representation of uint256
        "initCode": initCode,
        "callData": callData,
        "accountGasLimits": accountGasLimits,
        "preVerificationGas": preVerificationGas_str, # Keep as string representation of uint256
        "gasFees": gasFees,
        "paymasterAndData": paymasterAndData,
        "signature": signature
    }

    # Return as JSON string
    return json.dumps(output_dict, indent=2)


# --- UserOperation Hashing Logic ---

def keccak(data_bytes: bytes) -> bytes:
    """Calculates the Keccak-256 hash of the given bytes."""
    hasher = sha3.keccak_256()
    hasher.update(data_bytes)
    return hasher.digest()

def hex_to_bytes(hex_string: str) -> bytes:
    """Converts a hex string (with or without 0x prefix) to bytes."""
    if hex_string.startswith('0x'):
        return bytes.fromhex(hex_string[2:])
    return bytes.fromhex(hex_string)

def calculate_user_op_hash(user_op_json: str, entry_point_address: str, chain_id: int) -> str:
    """Calculates the userOpHash according to EIP-4337 EntryPoint logic.

    Args:
        user_op_json: The JSON string representation of the PackedUserOperation,
                      as generated by format_json_to_solidity_struct.
        entry_point_address: The address of the EntryPoint contract.
        chain_id: The chain ID.

    Returns:
        The userOpHash as a '0x'-prefixed hex string.
    """
    user_op = json.loads(user_op_json)

    # --- 1. Prepare data and calculate intermediate hashes --- 
    sender = user_op['sender'] # Already string, eth_abi handles validation
    try:
        nonce = int(user_op['nonce'])
    except ValueError:
        raise ValueError(f"Invalid nonce format: {user_op['nonce']}")
    
    init_code_bytes = hex_to_bytes(user_op['initCode'])
    call_data_bytes = hex_to_bytes(user_op['callData'])
    paymaster_and_data_bytes = hex_to_bytes(user_op['paymasterAndData'])

    hash_init_code = keccak(init_code_bytes)
    hash_call_data = keccak(call_data_bytes)
    hash_paymaster_and_data = keccak(paymaster_and_data_bytes)

    try:
        account_gas_limits_bytes = hex_to_bytes(user_op['accountGasLimits'])
        if len(account_gas_limits_bytes) != 32:
            raise ValueError("accountGasLimits must be 32 bytes")
    except (ValueError, KeyError):
        raise ValueError(f"Invalid accountGasLimits format: {user_op.get('accountGasLimits')}")

    try:
        pre_verification_gas = int(user_op['preVerificationGas'])
    except ValueError:
        raise ValueError(f"Invalid preVerificationGas format: {user_op['preVerificationGas']}")

    try:
        gas_fees_bytes = hex_to_bytes(user_op['gasFees'])
        if len(gas_fees_bytes) != 32:
            raise ValueError("gasFees must be 32 bytes")
    except (ValueError, KeyError):
        raise ValueError(f"Invalid gasFees format: {user_op.get('gasFees')}")

    # --- 2. Mimic `encode` function --- 
    packed_user_op_part_for_hash = encode(
        ['address', 'uint256', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'bytes32', 'bytes32'],
        [
            sender,
            nonce,
            hash_init_code,
            hash_call_data,
            account_gas_limits_bytes,
            pre_verification_gas,
            gas_fees_bytes,
            hash_paymaster_and_data
        ]
    )

    # --- 3. Mimic `hash` function --- 
    user_op_partial_hash = keccak(packed_user_op_part_for_hash)

    # --- 4. Mimic `getUserOpHash` --- 
    packed_final_for_hash = encode(
        ['bytes32', 'address', 'uint256'],
        [user_op_partial_hash, entry_point_address, chain_id]
    )

    user_op_hash = keccak(packed_final_for_hash)

    return '0x' + user_op_hash.hex()


# --- EIP-191 Hashing Functions ---

def eip191_hash_bytes(data_bytes: bytes) -> str:
    """Calculates the EIP-191 hash for the given bytes.

    Prepends '\x19Ethereum Signed Message:\n<length>' and hashes with Keccak-256.

    Args:
        data_bytes: The raw bytes to hash.

    Returns:
        The Keccak-256 hash as a '0x'-prefixed hex string.
    """
    prefix = b'\x19Ethereum Signed Message:\n' + str(len(data_bytes)).encode('ascii')
    message_to_hash = prefix + data_bytes
    
    hasher = sha3.keccak_256()
    hasher.update(message_to_hash)
    return '0x' + hasher.hexdigest()

def eip191_hash_message(message: str) -> str:
    """Calculates the EIP-191 hash for a UTF-8 string message.

    Args:
        message: The string message.

    Returns:
        The EIP-191 Keccak-256 hash as a '0x'-prefixed hex string.
    """
    message_bytes = message.encode('utf-8')
    return eip191_hash_bytes(message_bytes)

def eip191_hash_hex(hex_data: str) -> str:
    """Calculates the EIP-191 hash for data provided as a hex string.

    Useful for hashing existing hashes or other byte data represented in hex.

    Args:
        hex_data: The hex string (optionally '0x'-prefixed).

    Returns:
        The EIP-191 Keccak-256 hash as a '0x'-prefixed hex string.
    Raises:
        ValueError: If the hex_data is not a valid hex string.
    """
    if hex_data.startswith('0x'):
        hex_data = hex_data[2:]
    
    try:
        data_bytes = bytes.fromhex(hex_data)
    except ValueError:
        raise ValueError(f"Invalid hex string provided: {hex_data[:20]}...")
    
    return eip191_hash_bytes(data_bytes)


# --- Signature Recovery --- 
def recover_signer(digest_bytes: bytes, signature_hex: str) -> str | None:
    """Attempts to recover the signer's address from a digest and signature.

    Args:
        digest_bytes: The 32-byte hash (digest) that was signed.
        signature_hex: The signature as a 0x-prefixed hex string (65 bytes).

    Returns:
        The checksummed signer address as a string, or None if recovery fails.
    """

    if not signature_hex or signature_hex == '0x' or len(signature_hex) != 132: # 0x + 65 bytes * 2 hex chars/byte
        # print("Debug: Invalid or empty signature provided for recovery.")
        return None
    try:
        signature_bytes = hex_to_bytes(signature_hex)
        
        # --- Manual v value adjustment (as requested) ---
        # NOTE: This is generally NOT needed for eth_keys, which handles v=27/28.
        # Doing this manually might break recovery if the library expects 27/28.
        if len(signature_bytes) == 65:
            v = signature_bytes[-1]
            if v in (27, 28):
                # Adjust v to 0 or 1
                adjusted_v = v - 27 
                # Reconstruct signature bytes with adjusted v
                signature_bytes = signature_bytes[:-1] + bytes([adjusted_v])
                # print(f"Debug: Adjusted v from {v} to {adjusted_v}")
            # else: # Handle EIP-155? eth_keys should do this. Let's assume 27/28 for this adjustment.
                # print(f"Debug: v is {v}, not adjusting.")
        # --- End of manual adjustment ---

        signature = keys.Signature(signature_bytes=signature_bytes)
        # Ensure digest is 32 bytes
        if len(digest_bytes) != 32:
             # print(f"Debug: Digest must be 32 bytes for recovery, got {len(digest_bytes)}.")
             return None
        
        # Use the potentially modified signature object
        public_key = signature.recover_public_key_from_msg_hash(digest_bytes)
        return public_key.to_checksum_address()
    except (BadSignature, ValueError, TypeError, Exception) as e: # Catch potential errors
        # print(f"Debug: Recovery failed - {e}")
        return None



# --- Command-Line Execution Logic ---
def main():
    DEFAULT_ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" # v0.7

    parser = argparse.ArgumentParser(description="Parse raw UserOperation text, format to JSON, and calculate hashes.")
    parser.add_argument("raw_input", help="Raw UserOperation text data (like bundler debug output). Wrap in quotes if it contains spaces.")
    parser.add_argument("-c", "--chainId", type=int, required=True, help="Chain ID for UserOpHash calculation.")
    parser.add_argument("-e", "--entrypoint", default=DEFAULT_ENTRY_POINT, help=f"EntryPoint contract address (default: {DEFAULT_ENTRY_POINT}).")
    parser.add_argument("-s", "--signer", help="Optional: Expected signer address to verify against recovery results.")

    args = parser.parse_args()

    # Validate signer address format if provided
    if args.signer:
        if not isinstance(args.signer, str) or not args.signer.startswith('0x') or len(args.signer) != 42:
            print(f"Error: Invalid format for --signer address: {args.signer}")
            import sys
            sys.exit(1)
        try:
            # Basic hex check
            bytes.fromhex(args.signer[2:])
        except ValueError:
             print(f"Error: Invalid hex characters in --signer address: {args.signer}")
             import sys
             sys.exit(1)

    try:
        # 1. Parse raw text to intermediate JSON
        intermediate_json = parse_text_to_json(args.raw_input)
        # Load intermediate JSON once to get signature/sender before full formatting
        try:
             user_op_intermediate_data = json.loads(intermediate_json)
        except json.JSONDecodeError as e:
            print(f"\nError: Could not parse the initial text input into valid JSON: {e}")
            import sys
            sys.exit(1)

        # 2. Format intermediate JSON to PackedUserOperation JSON
        final_json = format_json_to_solidity_struct(intermediate_json)

        # 3. Calculate UserOpHash
        user_op_hash = calculate_user_op_hash(final_json, args.entrypoint, args.chainId)
        user_op_hash_bytes = hex_to_bytes(user_op_hash)

        # 4. Calculate EIP-191 hash of the UserOpHash *bytes*
        eip191_hash_of_hash_bytes_hex = eip191_hash_hex(user_op_hash)
        eip191_digest_bytes = hex_to_bytes(eip191_hash_of_hash_bytes_hex)

        # 5. Calculate EIP-191 hash of the UserOpHash *hex string itself* (as a message)
        eip191_hash_of_hash_string_hex = eip191_hash_message(user_op_hash)
        eip191_digest_string_bytes = hex_to_bytes(eip191_hash_of_hash_string_hex) # Bytes of the resulting hash

        # --- Print Core Results ---
        print("--- Formatted PackedUserOperation JSON ---")
        print(final_json)

        print("\n--- Calculated UserOpHash ---")
        print(user_op_hash)

        print("\n--- EIP-191 Hashes of UserOpHash ---")
        print(f"Hash of UserOpHash Bytes (eip191_hash_hex):    {eip191_hash_of_hash_bytes_hex}")
        print(f"Hash of UserOpHash String (eip191_hash_message): {eip191_hash_of_hash_string_hex}")

        # --- 6. Attempt Signature Recovery ---
        signature_hex = user_op_intermediate_data.get("signature")
        sender_address_from_op = user_op_intermediate_data.get("sender") # Used only for context now

        print("\n--- Signature Recovery --- ") # Renamed section slightly

        if not signature_hex or signature_hex == '0x':
            print("No signature provided in input.")
        elif len(signature_hex) != 132:
             print(f"Invalid signature length: {len(signature_hex)} characters (expected 132 for 0x + 65 bytes)")
        else:
            # Attempt recovery with the 3 digests
            recovered_from_userophash = recover_signer(user_op_hash_bytes, signature_hex)
            recovered_from_eip191_bytes = recover_signer(eip191_digest_bytes, signature_hex)
            recovered_from_eip191_string = recover_signer(eip191_digest_string_bytes, signature_hex)

            # --- Conditional Output based on --signer --- 
            if args.signer:
                # Mode: Verify against provided --signer
                print(f"Verifying signature against expected signer: {args.signer}")
                print(f"Signature provided: {signature_hex}")
                match_found_signer = False

                if recovered_from_userophash and recovered_from_userophash.lower() == args.signer.lower():
                    print(f"  ✅ Signature matches signer for Digest 1 (UserOpHash Bytes: 0x{user_op_hash_bytes.hex()})")
                    match_found_signer = True
                
                if recovered_from_eip191_bytes and recovered_from_eip191_bytes.lower() == args.signer.lower():
                    print(f"  ✅ Signature matches signer for Digest 2 (EIP-191 of UserOpHash Bytes: 0x{eip191_digest_bytes.hex()})")
                    match_found_signer = True

                if recovered_from_eip191_string and recovered_from_eip191_string.lower() == args.signer.lower():
                     print(f"  ✅ Signature matches signer for Digest 3 (EIP-191 of UserOpHash String: 0x{eip191_digest_string_bytes.hex()})")
                     match_found_signer = True
                
                if not match_found_signer:
                    print(f"  ❌ Signature did NOT recover the specified signer address ({args.signer}) for any tested digest.")
                    # Optionally print failed recovery attempts for debugging?
                    # print("  Recovery attempts:")
                    # print(f"    Digest 1 -> {recovered_from_userophash or 'Failed'}")
                    # print(f"    Digest 2 -> {recovered_from_eip191_bytes or 'Failed'}")
                    # print(f"    Digest 3 -> {recovered_from_eip191_string or 'Failed'}")

            else:
                # Mode: Show all recovery results (no --signer provided)
                if sender_address_from_op:
                    print(f"Sender Address (from Op, for context): {sender_address_from_op}")
                print(f"Signature:                             {signature_hex}")
                print("\nRecovery Results:")
                print("-" * 20)
                # Digest 1
                print(f"Digest 1 (UserOpHash Bytes): 0x{user_op_hash_bytes.hex()}")
                print(f"  Recovered Address: {recovered_from_userophash or 'Failed'}")
                print("-" * 20)
                # Digest 2
                print(f"Digest 2 (EIP-191 of UserOpHash Bytes): 0x{eip191_digest_bytes.hex()}")
                print(f"  Recovered Address: {recovered_from_eip191_bytes or 'Failed'}")
                print("-" * 20)
                # Digest 3
                print(f"Digest 3 (EIP-191 of UserOpHash String): 0x{eip191_digest_string_bytes.hex()}")
                print(f"  Recovered Address: {recovered_from_eip191_string or 'Failed'}")
                print("-" * 20)

    except Exception as e:
        print(f"\nError processing input: {e}")
        # Optionally exit with non-zero status
        # import sys
        # sys.exit(1)

if __name__ == "__main__":
    main()


