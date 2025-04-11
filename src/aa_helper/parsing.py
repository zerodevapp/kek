import json

# No relative import needed here as hex_to_bytes is not used directly in these functions

def parse_text_to_json(text_data: str) -> str:
    """
    Parses the provided text format into a JSON string.
    Handles simple numeric, hex strings, and gwei values.
    """
    parsed_data = {}
    lines = text_data.splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        colon_index = line.find(':')
        if colon_index == -1:
            continue

        key = line[:colon_index].strip()
        value = line[colon_index + 1:].strip()

        if value.isdigit():
            # Keep potentially large numbers as strings to preserve precision
            # unless they are clearly small integers.
            if key in ['callGasLimit', 'paymasterPostOpGasLimit', 'paymasterVerificationGasLimit', 'preVerificationGas', 'verificationGasLimit'] and len(value) < 18:
                try:
                    parsed_data[key] = int(value)
                except ValueError:
                    parsed_data[key] = value # Fallback
            else:
                parsed_data[key] = value
        elif value.startswith("0x") and all(c in '0123456789abcdefABCDEF' for c in value[2:]):
            parsed_data[key] = value
        else:
            # Keep gwei as string for later parsing
            if "gwei" in value.lower():
                 parsed_data[key] = value
            else:
                try:
                    if '.' in value or 'e' in value.lower():
                        parsed_data[key] = float(value)
                    else:
                        parsed_data[key] = value # Keep as string
                except ValueError:
                    parsed_data[key] = value

    return json.dumps(parsed_data, indent=2)


def format_json_to_solidity_struct(json_data: str) -> str:
    """
    Formats intermediate JSON into the final PackedUserOperation JSON string.
    Handles packing/concatenation logic.
    """
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid intermediate JSON provided for formatting: {e}")

    # Helper to safely get data and provide default values
    def get_data(key, default=None):
        return data.get(key, default)

    # Helper to format uint128 to hex (32 chars, no prefix)
    def format_uint128_hex_noprefix(val):
         if isinstance(val, str) and val.isdigit():
            try: val = int(val)
            except ValueError: raise ValueError(f"Cannot convert {val} to int for uint128")
         elif not isinstance(val, int):
            try: val = int(val)
            except (ValueError, TypeError): raise ValueError(f"Cannot convert {val} to int for uint128")
         if val < 0 or val >= (1 << 128):
             raise ValueError(f"Value {val} out of range for uint128")
         return f"{val:032x}"

    # Helper to convert gwei string/number to wei int
    def gwei_to_wei(gwei_input):
        if isinstance(gwei_input, (int, float)):
            return int(gwei_input * 1e9)
        if not isinstance(gwei_input, str):
            return 0 
        try:
            num_part = gwei_input.split()[0]
            gwei_float = float(num_part)
            return int(gwei_float * 1e9)
        except (ValueError, IndexError, TypeError):
            try: return int(float(gwei_input) * 1e9)
            except ValueError: raise ValueError(f"Could not parse gwei: {gwei_input}")

    # --- Field Processing --- 
    sender = get_data('sender', '0x' + '0' * 40)
    nonce_val = get_data('nonce', '0')
    nonce_str = str(nonce_val) # Keep as string
    callData = get_data('callData', '0x')
    preVerificationGas_val = get_data('preVerificationGas', '0')
    preVerificationGas_str = str(preVerificationGas_val) # Keep as string
    signature = get_data('signature', '0x')

    # initCode
    factory = get_data('factory')
    factoryData = get_data('factoryData', '0x')
    if factory and isinstance(factory, str) and factory.startswith('0x') and len(factory) == 42 and factory != ('0x' + '0' * 40):
        f_data_hex = factoryData[2:] if isinstance(factoryData, str) and factoryData.startswith('0x') else factoryData
        initCode = f"{factory}{f_data_hex}"
    else:
        initCode = '0x'

    # accountGasLimits
    try:
        verificationGasLimit_val = get_data('verificationGasLimit', 0)
        callGasLimit_val = get_data('callGasLimit', 0)
        accountGasLimits = f"0x{format_uint128_hex_noprefix(verificationGasLimit_val)}{format_uint128_hex_noprefix(callGasLimit_val)}"
    except ValueError as e:
        print(f"Warning: Could not format accountGasLimits ({e}). Defaulting.")
        accountGasLimits = '0x' + '0'*64

    # gasFees
    try:
        maxFeePerGas_wei = gwei_to_wei(get_data('maxFeePerGas', '0 gwei'))
        maxPriorityFeePerGas_wei = gwei_to_wei(get_data('maxPriorityFeePerGas', '0 gwei'))
        gasFees = f"0x{format_uint128_hex_noprefix(maxPriorityFeePerGas_wei)}{format_uint128_hex_noprefix(maxFeePerGas_wei)}"
    except ValueError as e:
         print(f"Warning: Could not format gasFees ({e}). Defaulting.")
         gasFees = '0x' + '0'*64

    # paymasterAndData
    paymaster = get_data('paymaster')
    paymasterData = get_data('paymasterData', '0x')
    if paymaster and isinstance(paymaster, str) and paymaster.startswith('0x') and len(paymaster) == 42 and paymaster != ('0x' + '0' * 40):
        pm_data_hex = paymasterData[2:] if isinstance(paymasterData, str) and paymasterData.startswith('0x') else paymasterData
        try:
            paymasterVerificationGasLimit_val = get_data('paymasterVerificationGasLimit', 0)
            paymasterPostOpGasLimit_val = get_data('paymasterPostOpGasLimit', 0)
            pm_ver_gas_hex = format_uint128_hex_noprefix(paymasterVerificationGasLimit_val)
            pm_post_gas_hex = format_uint128_hex_noprefix(paymasterPostOpGasLimit_val)
            paymasterAndData = f"{paymaster}{pm_ver_gas_hex}{pm_post_gas_hex}{pm_data_hex}"
        except ValueError as e:
            print(f"Warning: Could not format paymaster gas limits ({e}). Omitting.")
            paymasterAndData = f"{paymaster}{pm_data_hex}"
    else:
        paymasterAndData = '0x'

    output_dict = {
        "sender": sender,
        "nonce": nonce_str,
        "initCode": initCode,
        "callData": callData,
        "accountGasLimits": accountGasLimits,
        "preVerificationGas": preVerificationGas_str,
        "gasFees": gasFees,
        "paymasterAndData": paymasterAndData,
        "signature": signature
    }

    return json.dumps(output_dict, indent=2) 