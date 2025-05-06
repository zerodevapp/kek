import click
from web3 import Web3
from eth_abi import decode
from .constants import VALIDATORS, ZERO_ADDRESS

def explain_user_op(ctx, user_op_data: dict, rpc_url: str):
    """Parses and explains various fields of a UserOperation, including on-chain checks."""
    click.echo("--- UserOperation Explanation ---")

    # Initialize Web3
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        click.echo(f"Error: Could not connect to RPC URL: {rpc_url}", err=True)
        # Optionally exit or just continue without on-chain checks
        # For now, just print error and continue
        w3 = None # Set w3 to None to skip on-chain checks later

    # --- Sender Explanation ---
    sender_str = user_op_data.get('sender')
    if sender_str:
        click.echo(f"Sender: {sender_str}")
        if w3 and not w3.is_address(sender_str):
            click.echo("  Warning: Sender does not appear to be a valid checksum address.")
        # Add Kernel check later if sender is identified
    else:
        click.echo("Sender: Not found in input data.")
        sender_str = None # Ensure sender_str is None if not found

    # --- Nonce Explanation ---
    nonce_str = user_op_data.get('nonce')
    if nonce_str is None:
        # Try case-insensitive lookup if needed (though intermediate format should be consistent)
        for k, v in user_op_data.items():
            if k.lower() == 'nonce':
                nonce_str = v
                break

    if nonce_str is None:
        click.echo("Nonce: Not found in input data.")
    else:
        try:
            nonce_int = int(str(nonce_str), 0)
        except (ValueError, TypeError) as e:
            click.echo(f"Nonce: Error parsing value '{nonce_str}': {e}")
            nonce_int = None # Set to None on error

        if nonce_int is not None:
            click.echo(f"\nNonce (uint256): 0x{nonce_int:064x}")
            mode = (nonce_int >> 248) & 0xFF
            v_type = (nonce_int >> 240) & 0xFF
            identifier_int = (nonce_int >> (10 * 8)) & ((1 << (20 * 8)) - 1)
            nonce_key = (nonce_int >> (8*8)) & 0xFFFF
            sequence = nonce_int & ((1 << (8*8)) -1)

            # Format identifier for lookup
            identifier_addr = f"0x{identifier_int:040x}"
            validator_name = VALIDATORS.get(identifier_addr, "Unknown Validator")

            # Prepare data for ctx.print_table
            headers = ["Component", "Hex Value", "Notes"]
            
            # Determine Mode Notes
            if mode == 0:
                mode_notes = "default"
            elif mode == 1:
                mode_notes = "enable"
            else:
                mode_notes = f"Unknown Mode ({mode})"

            # Determine ValidationType Notes (placeholder)
            if v_type == 0:
                vtype_notes = "root"
            elif v_type == 1:
                vtype_notes = "validator"
            elif v_type == 2:
                vtype_notes = "permission"
            else:
                vtype_notes = f"Unknown Type ({v_type})"

            try:
                is_valid = check_validation_config(w3, sender_str, v_type, identifier_int)
            except Exception as e:
                click.echo(f"  Error during on-chain check: {e}")
                is_valid = False

            data = [
                ["Mode (byte 0)", f"0x{mode:02x}", mode_notes],
                ["ValidationType (1)", f"0x{v_type:02x}", vtype_notes],
                ["Identifier (2-21)", identifier_addr, validator_name + "(" + ("Active" if is_valid else "Inactive") + ")"],
                ["Nonce Key (22-23)", f"0x{nonce_key:04x}", ""],
                ["Sequence (24-31)", f"0x{sequence:016x}", ""]
            ]

            click.echo("\n  --- Parsed Nonce Components ---")
            ctx.print_table(data, headers)
            if not is_valid and mode != 1:
                click.echo(click.style("  Warning: Validator is inactive. This UserOperation might not be validated.", fg="red"))
            elif not is_valid and mode == 1:
                click.echo(click.style("  UserOp is on enable mode", fg="yellow"))

    # --- Add explanations for other fields later --- 
    click.echo("\n... (Explanation for other fields to be added)") 

def check_validation_config(w3, sender_str, v_type, identifier_int): 
    # --- On-chain Validation Check (if possible) ---
    if w3 and sender_str and w3.is_address(sender_str):
        click.echo("\n  --- On-chain Validation Config Check ---")
        # Construct the bytes21 argument: bytes1(ValidationType) + bytes20(Identifier)
        validation_arg_bytes21 = bytes([v_type]) + identifier_int.to_bytes(20, 'big')
        # Pad the 21-byte argument to 32 bytes for ABI encoding
        padded_validation_arg = validation_arg_bytes21.ljust(32, b'\x00')
        validation_config_selector = w3.keccak(text="validationConfig(bytes21)")[:4]
        calldata = validation_config_selector + padded_validation_arg # Use padded argument

        result = w3.eth.call({
            'to': sender_str, 
            'data': calldata
        })
        decoded_data = decode(['uint32','address'], result)
        if decoded_data[0] == 0 and decoded_data[1] == ZERO_ADDRESS:
            return False
        else:
            # actually you need to also check the account.currentNonce() too but let's keep it simple for now
            return True
