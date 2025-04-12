import json
import re # For simple JSON check

# --- Parsing Helpers ---

def parse_gas_value_to_wei(value) -> int:
    """Parses various gas value inputs (str, int, float) into wei (int)."""
    if isinstance(value, int):
        return value # Assume already in wei
    if isinstance(value, float):
        return int(value * 1e9) # Assume float represents gwei
    
    if not isinstance(value, str):
        raise ValueError(f"Cannot parse gas value of type {type(value)}")

    value_str = value.strip().lower()
    
    try:
        if value_str.endswith(" gwei"):
            num_part = value_str.replace(" gwei", "").strip()
            return int(float(num_part) * 1e9)
        elif value_str.startswith("0x"):
            return int(value_str, 16) # Assume hex is wei
        elif '.' in value_str or 'e' in value_str:
            return int(float(value_str) * 1e9) # Assume float notation is gwei
        else:
            return int(value_str) # Assume numeric string is wei
    except ValueError as e:
        raise ValueError(f"Could not parse gas value '{value}' to wei: {e}")

# --- Input Handling ---

def detect_and_load_input(input_str: str) -> dict:
    """Detects input format (raw text, UserOp JSON, Packed JSON) and loads into a dict."""
    input_str = input_str.strip()
    is_likely_json = input_str.startswith('{') and input_str.endswith('}')

    if is_likely_json:
        try:
            data = json.loads(input_str)
            if all(k in data for k in ["sender", "nonce", "accountGasLimits", "gasFees"]):
                # print("Detected PackedUserOperation JSON input.")
                # Need to convert packed fields back potentially, or treat as intermediate
                # Let's try to convert relevant fields for consistency
                for key in ["nonce", "preVerificationGas"]:
                     if key in data and isinstance(data[key], str) and data[key].startswith('0x'):
                         try: data[key] = int(data[key], 16)
                         except ValueError: pass
                # Gas fees might need unpacking? For now, pass as is.
                return data
            elif all(k in data for k in ["sender", "nonce", "callData"]):
                # print("Detected UserOperation JSON input.")
                # Normalize numeric fields (hex/int str -> int)
                for key in ["nonce", "callGasLimit", "verificationGasLimit", "preVerificationGas", "paymasterVerificationGasLimit", "paymasterPostOpGasLimit"]:
                    if key in data and isinstance(data[key], str) and data[key].startswith('0x'):
                        try: data[key] = int(data[key], 16)
                        except ValueError: pass 
                    elif key in data and isinstance(data[key], str) and data[key].isdigit():
                         try: data[key] = int(data[key])
                         except ValueError: pass
                         
                # Specifically parse gas fees to wei int
                for key in ["maxFeePerGas", "maxPriorityFeePerGas"]:
                     if key in data:
                         try: data[key] = parse_gas_value_to_wei(data[key])
                         except ValueError as e:
                             print(f"Warning: Could not parse JSON field '{key}': {e}. Skipping.")
                             data[key] = 0 # Default to 0 if parsing fails
                 
                return data
            else:
                print("Warning: Input looks like JSON but format is unrecognized. Treating as raw text.")
                pass
        except json.JSONDecodeError:
            pass

    # --- Assume Raw Text Parsing --- 
    # print("Assuming raw text input.")
    parsed_data = {}
    lines = input_str.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        colon_index = line.find(':')
        if colon_index == -1:
            continue
        key = line[:colon_index].strip()
        value_str = line[colon_index + 1:].strip()
        original_key = key # Keep original key case if needed elsewhere
        key = key.lower() # Use lower case for matching

        # Handle specific fields first
        if key in ["maxfeepergas", "maxpriorityfeepergas"]:
            try:
                parsed_data[original_key] = parse_gas_value_to_wei(value_str)
            except ValueError as e:
                print(f"Warning: Could not parse gas value for '{original_key}': {e}. Storing as string.")
                parsed_data[original_key] = value_str # Store original if parse fails
        elif value_str.isdigit():
             if key in ['callgaslimit', 'verificationgaslimit', 'preverificationgas', 'paymasterverificationgaslimit', 'paymasterpostopgaslimit'] and len(value_str) < 18:
                 try: parsed_data[original_key] = int(value_str)
                 except ValueError: parsed_data[original_key] = value_str
             else: parsed_data[original_key] = value_str # Keep large numbers like nonce as string
        elif value_str.startswith("0x") and all(c in '0123456789abcdefABCDEF' for c in value_str[2:]):
             if key in ["nonce", "callgaslimit", "verificationgaslimit", "preverificationgas", "paymasterverificationgaslimit", "paymasterpostopgaslimit"]:
                 try: parsed_data[original_key] = int(value_str, 16)
                 except ValueError: parsed_data[original_key] = value_str
             else:
                  parsed_data[original_key] = value_str # Keep addresses, data, etc. as strings
        else:
             # Keep gwei strings as is for other fields (if any), or just store string
            parsed_data[original_key] = value_str
            
    return parsed_data


def format_user_op_data(user_op_data: dict) -> str:
    """
    Formats intermediate UserOperation data (dict) into the final 
    PackedUserOperation JSON string, handling optional fields.
    
    Args:
        user_op_data: Dictionary representing the UserOperation.

    Returns:
        A JSON string representation of the PackedUserOperation.
    """
    # Helper to safely get data and provide default values
    def get_data(key, default=None):
        # Prioritize direct key, then case-insensitive for common variations
        val = user_op_data.get(key, None)
        if val is not None: return val
        # Try common case variations if initial lookup fails
        for k, v in user_op_data.items():
            if k.lower() == key.lower(): return v
        return default

    # --- Optional Field Defaults --- 
    ZERO_ADDRESS = '0x' + '0' * 40
    EMPTY_BYTES = '0x'
    ZERO_BYTES32 = '0x' + '0' * 64

    # Get data - gas fees should now be integers (wei)
    factory = get_data('factory')
    factoryData = get_data('factoryData')
    paymaster = get_data('paymaster')
    paymasterData = get_data('paymasterData')
    paymasterVerificationGasLimit_in = get_data('paymasterVerificationGasLimit', 0)
    paymasterPostOpGasLimit_in = get_data('paymasterPostOpGasLimit', 0)
    verificationGasLimit_in = get_data('verificationGasLimit', 0)
    callGasLimit_in = get_data('callGasLimit', 0)
    maxFeePerGas_in = get_data('maxFeePerGas', 0) # Default to 0 (int wei)
    maxPriorityFeePerGas_in = get_data('maxPriorityFeePerGas', 0) # Default to 0 (int wei)
    preVerificationGas_in = get_data('preVerificationGas', '0') # Keep as string/int for now
    nonce_in = get_data('nonce', '0') # Keep as string/int for now
    sender_in = get_data('sender', ZERO_ADDRESS)
    callData_in = get_data('callData', EMPTY_BYTES)
    signature_in = get_data('signature', EMPTY_BYTES)

    # --- Format/Pack Required and Optional Fields --- 

    # Helper to format uint128 to hex (32 chars, no prefix)
    def format_uint128_hex_noprefix(val):
         if isinstance(val, str):
            try: val = int(val) if not val.startswith('0x') else int(val, 16)
            except ValueError: raise ValueError(f"Cannot convert {val} to int for uint128")
         elif not isinstance(val, int):
            try: val = int(val)
            except (ValueError, TypeError): raise ValueError(f"Cannot convert {val} to int for uint128")
         if val < 0 or val >= (1 << 128):
             raise ValueError(f"Value {val} out of range for uint128")
         return f"{val:032x}"

    # Nonce & PreVerificationGas (convert hex/int string to simple string)
    nonce_str = str(nonce_in) if not (isinstance(nonce_in, str) and nonce_in.startswith('0x')) else str(int(nonce_in, 16))
    preVerificationGas_str = str(preVerificationGas_in) if not (isinstance(preVerificationGas_in, str) and preVerificationGas_in.startswith('0x')) else str(int(preVerificationGas_in, 16))

    # initCode
    if factory and factory != ZERO_ADDRESS:
        factoryData_val = factoryData if factoryData else EMPTY_BYTES
        f_data_hex = factoryData_val[2:] if factoryData_val.startswith('0x') else factoryData_val
        initCode = f"{factory}{f_data_hex}"
    else:
        initCode = EMPTY_BYTES

    # accountGasLimits
    try:
        accountGasLimits = f"0x{format_uint128_hex_noprefix(verificationGasLimit_in)}{format_uint128_hex_noprefix(callGasLimit_in)}"
    except ValueError as e:
        print(f"Warning: Could not format accountGasLimits ({e}). Defaulting.")
        accountGasLimits = ZERO_BYTES32

    # gasFees (use integer wei values directly)
    try:
        gasFees = f"0x{format_uint128_hex_noprefix(maxPriorityFeePerGas_in)}{format_uint128_hex_noprefix(maxFeePerGas_in)}"
    except ValueError as e:
         print(f"Warning: Could not format gasFees ({e}). Input Values: Prio={maxPriorityFeePerGas_in}, Max={maxFeePerGas_in}. Defaulting.")
         gasFees = ZERO_BYTES32

    # paymasterAndData
    if paymaster and paymaster != ZERO_ADDRESS:
        pm_data_val = paymasterData if paymasterData else EMPTY_BYTES
        pm_data_hex = pm_data_val[2:] if pm_data_val.startswith('0x') else pm_data_val
        try:
            pm_ver_gas_hex = format_uint128_hex_noprefix(paymasterVerificationGasLimit_in)
            pm_post_gas_hex = format_uint128_hex_noprefix(paymasterPostOpGasLimit_in)
            paymasterAndData = f"{paymaster}{pm_ver_gas_hex}{pm_post_gas_hex}{pm_data_hex}"
        except ValueError as e:
            print(f"Warning: Could not format paymaster gas limits ({e}). Omitting.")
            paymasterAndData = f"{paymaster}{pm_data_hex}"
    else:
        paymasterAndData = EMPTY_BYTES

    # Final Output Dict Construction
    output_dict = {
        "sender": sender_in,
        "nonce": nonce_str,
        "initCode": initCode,
        "callData": callData_in if callData_in else EMPTY_BYTES,
        "accountGasLimits": accountGasLimits,
        "preVerificationGas": preVerificationGas_str,
        "gasFees": gasFees,
        "paymasterAndData": paymasterAndData,
        "signature": signature_in if signature_in else EMPTY_BYTES
    }

    return json.dumps(output_dict, indent=2)

# Remove original parse_text_to_json function if it exists above
# Remove original format_json_to_solidity_struct function if it exists above 