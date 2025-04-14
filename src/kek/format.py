import json

# Use relative imports for shared utility

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

def to_int_if_hex(value):
    """Converts a hex string (0x...) to int, otherwise returns original."""
    if isinstance(value, str) and value.startswith('0x'):
        try:
            return int(value, 16)
        except ValueError:
            return value # Return original if not valid hex
    return value

def unpack_uint128_pair(packed_hex: str) -> tuple[int, int]:
    """Unpacks a bytes32 hex string into two uint128 integers."""
    if not isinstance(packed_hex, str) or not packed_hex.startswith('0x') or len(packed_hex) != 66:
        raise ValueError(f"Invalid packed hex format for unpacking: '{packed_hex}'")
    try:
        val1_hex = packed_hex[2:34]  # First 128 bits (32 hex chars)
        val2_hex = packed_hex[34:]   # Second 128 bits (32 hex chars)
        return int(val1_hex, 16), int(val2_hex, 16)
    except ValueError as e:
        raise ValueError(f"Could not unpack hex string '{packed_hex}': {e}")

# --- Input Handling & Normalization ---

def detect_and_load_input(input_str: str) -> dict:
    """Detects input format and normalizes to a consistent intermediate dict format."""
    input_str = input_str.strip()
    is_likely_json = input_str.startswith('{') and input_str.endswith('}')
    data = {}

    if is_likely_json:
        try:
            raw_data = json.loads(input_str)
            normalized_data = {k.lower(): v for k, v in raw_data.items()} 
            data.update(normalized_data)
            # print("Detected JSON input.")
            # Check if it's likely PackedUserOp JSON AFTER initial load
            if all(k in data for k in ["sender", "nonce", "accountgaslimits", "gasfees"]):
                # print("Detected PackedUserOperation JSON input. Unpacking...")
                # Unpack gas limits
                try:
                    vgl_unpacked, cgl_unpacked = unpack_uint128_pair(data.get('accountgaslimits', '0x' + '0'*64))
                    data['verificationgaslimit'] = vgl_unpacked
                    data['callgaslimit'] = cgl_unpacked
                except ValueError as e:
                    print(f"Warning: Failed to unpack accountGasLimits from input: {e}")
                # Unpack gas fees
                try:
                    prio_unpacked, max_unpacked = unpack_uint128_pair(data.get('gasfees', '0x' + '0'*64))
                    # Note the order: prio first, then max in Packed format
                    data['maxpriorityfeepergas'] = prio_unpacked
                    data['maxfeepergas'] = max_unpacked
                except ValueError as e:
                     print(f"Warning: Failed to unpack gasFees from input: {e}")
                # We don't delete the packed keys, normalization below will handle types
            
            # Fallthrough to normalize all loaded JSON data

        except json.JSONDecodeError:
            is_likely_json = False # Treat as raw text if JSON parsing fails

    if not is_likely_json:
        # print("Assuming raw text input.")
        lines = input_str.splitlines()
        temp_data = {}
        for line in lines:
            line = line.strip()
            if not line: continue
            colon_index = line.find(':')
            if colon_index == -1: continue
            key = line[:colon_index].strip().lower() # Normalize key
            value_str = line[colon_index + 1:].strip()
            temp_data[key] = value_str # Store value as string for now
        data.update(temp_data)

    # --- Normalize values to consistent types (applies to ALL input types now) --- 
    normalized_output = {}
    int_keys = ["nonce", "callgaslimit", "verificationgaslimit", "preverificationgas", "paymasterverificationgaslimit", "paymasterpostopgaslimit"]
    gas_keys = ["maxfeepergas", "maxpriorityfeepergas"]
    # Include packed keys here, but they will be handled as hex strings
    hex_keys = ["sender", "initcode", "calldata", "accountgaslimits", "gasfees", "paymasteranddata", "signature", "factory", "factorydata", "paymaster", "paymasterdata"]

    for key, value in data.items():
        l_key = key.lower()
        output_key = l_key 
        
        if output_key in int_keys:
            try:
                # Ensure it's not None before converting
                if value is None: raise TypeError("None value for int key")
                normalized_output[output_key] = int(value, 16) if isinstance(value, str) and value.startswith('0x') else int(value)
            except (ValueError, TypeError):
                print(f"Warning: Could not convert '{key}' value '{value}' to int. Setting to 0.")
                normalized_output[output_key] = 0 # Default to 0 on error
        elif output_key in gas_keys:
             try:
                if value is None: raise TypeError("None value for gas key")
                normalized_output[output_key] = parse_gas_value_to_wei(value)
             except (ValueError, TypeError) as e:
                 print(f"Warning: Could not parse gas value for '{key}': {e}. Setting to 0.")
                 normalized_output[output_key] = 0
        elif output_key in hex_keys:
             if isinstance(value, str):
                 if value.startswith('0x'):
                     normalized_output[output_key] = value
                 elif not value.startswith('0x') and all(c in '0123456789abcdefABCDEF' for c in value):
                     normalized_output[output_key] = '0x' + value
                 elif value == "": # Handle empty strings for bytes
                      normalized_output[output_key] = '0x'
                 else:
                     # Might be a non-hex string mistakenly assigned (e.g. from raw text)
                     print(f"Warning: Non-hex value '{value}' found for expected hex field '{key}'. Setting to '0x'.")
                     normalized_output[output_key] = '0x' 
             elif value is None:
                 normalized_output[output_key] = '0x'
             else:
                 print(f"Warning: Unexpected type '{type(value)}' for hex field '{key}'. Setting to '0x'.")
                 normalized_output[output_key] = '0x'
        else:
             normalized_output[output_key] = value
             
    return normalized_output


def format_user_op_data(user_op_data: dict) -> str:
    """
    Formats normalized UserOperation data (dict) into the final 
    PackedUserOperation JSON string, handling optional fields and packing.
    """
    # Helper to safely get data (case-insensitive keys already handled by normalization)
    def get_data(key, default=None):
        return user_op_data.get(key, default)

    # --- Optional Field Defaults & Constants --- 
    ZERO_ADDRESS = '0x' + '0' * 40
    EMPTY_BYTES = '0x'
    ZERO_BYTES32 = '0x' + '0' * 64

    # --- Format/Pack Fields --- 

    # Helper to format uint128 to hex (32 chars, no prefix)
    def format_uint128_hex_noprefix(val):
         val = to_int_if_hex(val) # Convert hex string to int first if needed
         if not isinstance(val, int):
            try: val = int(val)
            except (ValueError, TypeError): raise ValueError(f"Cannot convert '{val}' to int for uint128")
         if val < 0 or val >= (1 << 128):
             raise ValueError(f"Value {val} out of range for uint128")
         return f"{val:032x}"

    # Get core fields (expecting specific types from normalization)
    sender = get_data('sender', ZERO_ADDRESS)
    nonce = get_data('nonce', 0)
    preVerificationGas = get_data('preverificationgas', 0)
    callData = get_data('calldata', EMPTY_BYTES)
    signature = get_data('signature', EMPTY_BYTES)
    maxFeePerGas = get_data('maxfeepergas', 0)
    maxPriorityFeePerGas = get_data('maxpriorityfeepergas', 0)
    callGasLimit = get_data('callgaslimit', 0)
    verificationGasLimit = get_data('verificationgaslimit', 0)
    
    # Handle initCode (prioritize existing, then construct)
    initCode = get_data('initcode', None)
    if initCode is None:
        factory = get_data('factory')
        factoryData = get_data('factorydata', EMPTY_BYTES) 
        if factory and factory != ZERO_ADDRESS:
            f_data_hex = factoryData[2:] if factoryData.startswith('0x') else factoryData
            initCode = f"{factory}{f_data_hex}"
        else:
            initCode = EMPTY_BYTES
    elif not isinstance(initCode, str) or not initCode.startswith('0x'):
         print(f"Warning: Provided initCode '{initCode}' is not a valid hex string. Using '0x'.")
         initCode = EMPTY_BYTES

    # Handle paymasterAndData (prioritize existing, then construct)
    paymasterAndData = get_data('paymasteranddata', None)
    if paymasterAndData is None:
        paymaster = get_data('paymaster')
        paymasterData = get_data('paymasterdata', EMPTY_BYTES)
        if paymaster and paymaster != ZERO_ADDRESS:
            pm_data_hex = paymasterData[2:] if paymasterData.startswith('0x') else paymasterData
            try:
                pmVg = get_data('paymasterverificationgaslimit', 0)
                pmPg = get_data('paymasterpostopgaslimit', 0)
                pm_ver_gas_hex = format_uint128_hex_noprefix(pmVg)
                pm_post_gas_hex = format_uint128_hex_noprefix(pmPg)
                paymasterAndData = f"{paymaster}{pm_ver_gas_hex}{pm_post_gas_hex}{pm_data_hex}"
            except ValueError as e:
                print(f"Warning: Could not format paymaster gas limits ({e}). Omitting gas limits.")
                paymasterAndData = f"{paymaster}{pm_data_hex}" # Fallback without gas limits
        else:
            paymasterAndData = EMPTY_BYTES
    elif not isinstance(paymasterAndData, str) or not paymasterAndData.startswith('0x'):
         print(f"Warning: Provided paymasterAndData '{paymasterAndData}' is not a valid hex string. Using '0x'.")
         paymasterAndData = EMPTY_BYTES

    # Pack accountGasLimits
    try:
        accountGasLimits = f"0x{format_uint128_hex_noprefix(verificationGasLimit)}{format_uint128_hex_noprefix(callGasLimit)}"
    except ValueError as e:
        print(f"Warning: Could not format accountGasLimits ({e}). Defaulting.")
        accountGasLimits = ZERO_BYTES32

    # Pack gasFees
    try:
        gasFees = f"0x{format_uint128_hex_noprefix(maxPriorityFeePerGas)}{format_uint128_hex_noprefix(maxFeePerGas)}"
    except ValueError as e:
         print(f"Warning: Could not format gasFees ({e}). Input Values: Prio={maxPriorityFeePerGas}, Max={maxFeePerGas}. Defaulting.")
         gasFees = ZERO_BYTES32

    # Final Output Dict Construction
    output_dict = {
        "sender": sender,
        "nonce": str(nonce), # Store as string
        "initCode": initCode,
        "callData": callData,
        "accountGasLimits": accountGasLimits,
        "preVerificationGas": str(preVerificationGas), # Store as string
        "gasFees": gasFees,
        "paymasterAndData": paymasterAndData,
        "signature": signature
    }

    return json.dumps(output_dict, indent=2)

def format_to_user_op_json(user_op_data: dict) -> str:
    """
    Formats normalized UserOperation data (dict) into the standard
    EIP-4337 UserOperation JSON structure (numbers as hex strings).
    Handles optional fields, using defaults if missing.
    """
    # Helper to safely get data (case-insensitive keys already handled by normalization)
    def get_data(key, default=None):
        return user_op_data.get(key, default)

    # --- Optional Field Defaults & Constants ---
    ZERO_ADDRESS = '0x' + '0' * 40
    EMPTY_BYTES = '0x'
    ZERO_INT = 0

    # --- Get Normalized Data (expecting ints/hex strings from detect_and_load_input) ---
    # Use lowercase keys as defined in the normalization step
    sender = get_data('sender', ZERO_ADDRESS)
    nonce = get_data('nonce', ZERO_INT)
    factory = get_data('factory') # Get potential factory address
    factoryData = get_data('factorydata') # Get potential factory data
    initCode = get_data('initcode') # Get potential pre-built initCode
    callData = get_data('calldata', EMPTY_BYTES)
    callGasLimit = get_data('callgaslimit', ZERO_INT)
    verificationGasLimit = get_data('verificationgaslimit', ZERO_INT)
    preVerificationGas = get_data('preverificationgas', ZERO_INT)
    maxFeePerGas = get_data('maxfeepergas', ZERO_INT) # Expecting wei int
    maxPriorityFeePerGas = get_data('maxpriorityfeepergas', ZERO_INT) # Expecting wei int
    paymaster = get_data('paymaster') # Get potential paymaster address
    paymasterVerificationGasLimit = get_data('paymasterverificationgaslimit', ZERO_INT) # Use ZERO_INT default
    paymasterPostOpGasLimit = get_data('paymasterpostopgaslimit', ZERO_INT) # Use ZERO_INT default
    paymasterData = get_data('paymasterdata') # Get potential paymaster data
    paymasterAndData = get_data('paymasteranddata') # Get potential pre-built paymasterAndData
    signature = get_data('signature', EMPTY_BYTES)

    # --- Build the UserOperation JSON dictionary IN ORDER --- 
    # Using a temporary list of tuples to maintain order before json.dumps
    ordered_items = []

    # Add sender and nonce first
    ordered_items.append(("sender", sender))
    ordered_items.append(("nonce", hex(to_int_if_hex(nonce))))

    # Handle Factory/InitCode
    if factory and factory != ZERO_ADDRESS:
        ordered_items.append(("factory", factory))
        ordered_items.append(("factoryData", factoryData if factoryData else EMPTY_BYTES))
    elif initCode and initCode != EMPTY_BYTES:
        # initCode = bytes20(factory) + factoryData
        # make sure you don't forget the 0x prefix, and initCode is also prefixed with 0x
        ordered_items.append(("factory", initCode[:42]))
        ordered_items.append(("factoryData", "0x" + initCode[42:]))
        # print("Warning: Including pre-built 'initCode'. Cannot reliably split into factory/factoryData.")
    # else: implicitly skip if neither factory nor initCode is present

    # Add core execution fields
    ordered_items.append(("callData", callData if callData else EMPTY_BYTES))
    ordered_items.append(("callGasLimit", hex(to_int_if_hex(callGasLimit))))
    ordered_items.append(("verificationGasLimit", hex(to_int_if_hex(verificationGasLimit))))
    ordered_items.append(("preVerificationGas", hex(to_int_if_hex(preVerificationGas))))
    ordered_items.append(("maxFeePerGas", hex(maxFeePerGas)))
    ordered_items.append(("maxPriorityFeePerGas", hex(maxPriorityFeePerGas)))

    # Handle Paymaster/PaymasterAndData
    if paymaster and paymaster != ZERO_ADDRESS:
        ordered_items.append(("paymaster", paymaster))
        ordered_items.append(("paymasterVerificationGasLimit", hex(to_int_if_hex(paymasterVerificationGasLimit))))
        ordered_items.append(("paymasterPostOpGasLimit", hex(to_int_if_hex(paymasterPostOpGasLimit))))
        ordered_items.append(("paymasterData", paymasterData if paymasterData else EMPTY_BYTES))
    elif paymasterAndData and paymasterAndData != EMPTY_BYTES:
        # paymasterAndData = bytes20(paymaster) + paymasterVerificationGasLimit + paymasterPostOpGasLimit + paymasterData
        # make sure you don't forget the 0x prefix, and paymasterAndData is also prefixed with 0x
        ordered_items.append(("paymaster", paymasterAndData[:42]))
        ordered_items.append(("paymasterVerificationGasLimit", hex(to_int_if_hex("0x" + paymasterAndData[42:74])))) # format this to uint hex
        ordered_items.append(("paymasterPostOpGasLimit", hex(to_int_if_hex("0x" + paymasterAndData[74:106])))) # format this to uint hex
        ordered_items.append(("paymasterData", "0x" + paymasterAndData[106:]))
    # else: implicitly skip if neither paymaster info nor paymasterAndData is present

    # Add signature last
    ordered_items.append(("signature", signature if signature else EMPTY_BYTES))

    # Convert the ordered list of tuples into a proper OrderedDict and use standard json serialization
    # Python 3.7+ dictionaries preserve insertion order, so this will maintain our key order
    ordered_dict = {}
    for key, value in ordered_items:
        ordered_dict[key] = value
    
    # Use standard json.dumps with proper indentation
    return json.dumps(ordered_dict, indent=2)

# Remove original parse_text_to_json function if it exists above
# Remove original format_json_to_solidity_struct function if it exists above 