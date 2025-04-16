import sys
import traceback
import click # Import click

# Relative imports for package modules
# from .parsing import parse_text_to_json, format_json_to_solidity_struct
from .format import detect_and_load_input, format_user_op_data, format_to_user_op_json # Updated imports
from .hashing import calculate_user_op_hash, eip191_hash_hex, eip191_hash_message, hex_to_bytes
from .signature import recover_signer
from .debug import encode_debug_command
from .simulate import encode_simulate_command
from .constants import ENTRY_POINT_V07

DEFAULT_ENTRY_POINT = ENTRY_POINT_V07

# --- Main Click Group --- 
@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    """KEK: Kernel Examination Kit

    A CLI tool to parse, format, hash, verify signatures, and debug 
    EIP-4337 UserOperations, especially for Kernel.
    """
    pass

# --- Helper to load input (used by multiple commands) ---
def load_input_data(raw_input_str):
    try:
        user_op_intermediate_data = detect_and_load_input(raw_input_str)
        if not user_op_intermediate_data:
            click.echo("\nError: Could not parse input data.", err=True)
            sys.exit(1)
        return user_op_intermediate_data
    except Exception as e:
        click.echo(f"\nError processing input: {e}", err=True)
        traceback.print_exc() # Still useful for debugging
        sys.exit(1)

# --- `format` command ---
@cli.command('format')
@click.argument('raw_input', type=str)
@click.option('--output', '-o', type=click.Choice(['packed', 'userop'], case_sensitive=False), default='packed', 
              help="Output format: 'packed' (default) or 'userop'.")
def format_cmd(raw_input, output):
    """Parse/normalize input and output JSON in specified format."""
    user_op_intermediate_data = load_input_data(raw_input)
    
    try:
        if output == 'userop':
            output_json = format_to_user_op_json(user_op_intermediate_data)
            click.echo("--- Standard UserOperation JSON ---")
            click.echo(output_json)
        else: # Default is 'packed'
            output_json = format_user_op_data(user_op_intermediate_data)
            click.echo("--- Formatted PackedUserOperation JSON ---")
            click.echo(output_json)
    except Exception as e:
        click.echo(f"\nAn error occurred during formatting: {e}", err=True)
        traceback.print_exc()
        sys.exit(1)

# --- `userOpHash` command ---
@cli.command('userOpHash')
@click.argument('raw_input', type=str)
@click.option('--chainId', '-c', type=int, required=True, help="Chain ID for hash calculation.")
@click.option('--entrypoint', '-e', default=DEFAULT_ENTRY_POINT, 
              help=f"EntryPoint address (default: {DEFAULT_ENTRY_POINT}).")
def user_op_hash_cmd(raw_input, chainid, entrypoint):
    """Calculate the EIP-4337 UserOperation hash."""
    user_op_intermediate_data = load_input_data(raw_input)
    try:
        final_json = format_user_op_data(user_op_intermediate_data)
        user_op_hash = calculate_user_op_hash(final_json, entrypoint, chainid)
        click.echo("--- Calculated UserOpHash ---")
        click.echo(user_op_hash)
    except Exception as e:
        click.echo(f"\nAn error occurred during hash calculation: {e}", err=True)
        traceback.print_exc()
        sys.exit(1)

# --- `signer` command ---
@cli.command('signer')
@click.argument('raw_input', type=str)
@click.option('--chainId', '-c', type=int, required=True, help="Chain ID for hash calculation.")
@click.option('--entrypoint', '-e', default=DEFAULT_ENTRY_POINT, 
              help=f"EntryPoint address (default: {DEFAULT_ENTRY_POINT}).")
@click.option('--signer', '-s', 'expected_signer_address', # Store in this variable
              help="Optional: Verify signature against this address. If flag used without address, show all results.")
@click.option('--verify-only', is_flag=True, default=False, help="Only verify against --signer, don't show all results if flag used alone.")
def signer_cmd(raw_input, chainid, entrypoint, expected_signer_address, verify_only):
    """Recover signer or verify signature against expected address."""
    user_op_intermediate_data = load_input_data(raw_input)
    
    # Determine mode based on presence and type of expected_signer_address
    mode = 'skip'
    if expected_signer_address is not None:
        # Validate address if provided
        if isinstance(expected_signer_address, str):
             if not expected_signer_address.startswith('0x') or len(expected_signer_address) != 42:
                 click.echo(f"Error: Invalid format for --signer address: {expected_signer_address}", err=True)
                 sys.exit(1)
             try: bytes.fromhex(expected_signer_address[2:])
             except ValueError: 
                 click.echo(f"Error: Invalid hex characters in --signer address: {expected_signer_address}", err=True)
                 sys.exit(1)
             mode = 'verify'
        else: # Flag used alone (const=True not directly usable here, check type if needed or rely on click validation)
             if not verify_only:
                 mode = 'show_all'
             else:
                 # If --verify-only is set but no address given, it's an error or just skip
                 click.echo("Error: --verify-only requires an address provided via --signer.", err=True)
                 sys.exit(1)

    if mode == 'skip':
        click.echo("\n--- Signature Recovery Skipped (no --signer flag provided) ---")
        return

    try:
        # Format and calculate hashes needed for recovery
        final_json = format_user_op_data(user_op_intermediate_data)
        user_op_hash = calculate_user_op_hash(final_json, entrypoint, chainid)
        user_op_hash_bytes = hex_to_bytes(user_op_hash)
        eip191_hash_of_hash_bytes_hex = eip191_hash_hex(user_op_hash)
        eip191_digest_bytes = hex_to_bytes(eip191_hash_of_hash_bytes_hex)
        eip191_hash_of_hash_string_hex = eip191_hash_message(user_op_hash)
        eip191_digest_string_bytes = hex_to_bytes(eip191_hash_of_hash_string_hex)

        click.echo("\n--- Signature Recovery --- ")
        signature_hex = user_op_intermediate_data.get("signature")
        if not signature_hex:
             for k, v in user_op_intermediate_data.items():
                 if k.lower() == "signature": signature_hex = v; break

        if not signature_hex or signature_hex == '0x':
            click.echo("No signature provided in input.")
            return
        elif len(signature_hex) != 132:
            click.echo(f"Invalid signature length: {len(signature_hex)} chars (expected 132)", err=True)
            return
        
        # Perform recovery
        recovered_from_userophash = recover_signer(user_op_hash_bytes, signature_hex)
        recovered_from_eip191_bytes = recover_signer(eip191_digest_bytes, signature_hex)
        recovered_from_eip191_string = recover_signer(eip191_digest_string_bytes, signature_hex)

        if mode == 'verify':
            click.echo(f"Verifying signature against expected signer: {expected_signer_address}")
            click.echo(f"Signature provided: {signature_hex}")
            match_found_signer = False
            if recovered_from_userophash and recovered_from_userophash.lower() == expected_signer_address.lower():
                click.echo("  ✅ Matches signer for Digest 1 (UserOpHash Bytes)")
                match_found_signer = True
            if recovered_from_eip191_bytes and recovered_from_eip191_bytes.lower() == expected_signer_address.lower():
                click.echo("  ✅ Matches signer for Digest 2 (EIP-191 Bytes)")
                match_found_signer = True
            if recovered_from_eip191_string and recovered_from_eip191_string.lower() == expected_signer_address.lower():
                click.echo("  ✅ Matches signer for Digest 3 (EIP-191 String)")
                match_found_signer = True
            if not match_found_signer:
                click.echo(f"  ❌ Signature did NOT recover specified signer ({expected_signer_address}).")
        
        elif mode == 'show_all':
            sender_from_op = user_op_intermediate_data.get("sender")
            if not sender_from_op: 
                for k, v in user_op_intermediate_data.items():
                    if k.lower() == "sender": sender_from_op = v; break
            if sender_from_op: click.echo(f"Sender (from Op): {sender_from_op}")
            click.echo(f"Signature:        {signature_hex}")
            click.echo("\nShowing all recovery results:")
            click.echo("-"*20)
            click.echo(f"Digest 1 (UserOpHash): 0x{user_op_hash_bytes.hex()}")
            click.echo(f"  Recovered: {recovered_from_userophash or 'Failed'}")
            click.echo("-"*20)
            click.echo(f"Digest 2 (EIP-191 Bytes): 0x{eip191_digest_bytes.hex()}")
            click.echo(f"  Recovered: {recovered_from_eip191_bytes or 'Failed'}")
            click.echo("-"*20)
            click.echo(f"Digest 3 (EIP-191 String): 0x{eip191_digest_string_bytes.hex()}")
            click.echo(f"  Recovered: {recovered_from_eip191_string or 'Failed'}")
            click.echo("-"*20)

    except Exception as e:
        click.echo(f"\nAn error occurred during signer recovery/verification: {e}", err=True)
        traceback.print_exc()
        sys.exit(1)

# --- `debug` command ---
@cli.command('debug')
@click.argument('raw_input', type=str)
@click.option('--rpc-url', required=True, help="RPC URL for the cast command.")
def debug_cmd(raw_input, rpc_url):
    """Generate or execute `cast call --trace` for EntryPoint.handleOps."""
    user_op_intermediate_data = load_input_data(raw_input)
    # Pass args as a simple object/dict if needed by encode_debug_command
    class Args: pass
    debug_args = Args()
    debug_args.rpc_url = rpc_url
    
    encode_debug_command(debug_args, user_op_intermediate_data)

# --- `simulate` command ---
@cli.command('simulate')
@click.argument('raw_input', type=str)
@click.option('--rpc-url', required=True, help="RPC URL for the estimation command.")
def simulate_cmd(raw_input, rpc_url):
    """Simulate a UserOperation with Pimlico estimation address."""
    user_op_intermediate_data = load_input_data(raw_input)
    # Pass args as a simple object/dict if needed by encode_simulate_command
    class Args: pass
    simulate_args = Args()
    simulate_args.rpc_url = rpc_url
    
    try:
        encode_simulate_command(simulate_args, user_op_intermediate_data)
    except Exception as e:
        click.echo(f"\nAn error occurred during simulation: {e}", err=True)
        traceback.print_exc()
        sys.exit(1)

# --- Entry point for `kek` command ---
if __name__ == '__main__':
    cli() 