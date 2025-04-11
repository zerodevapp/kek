import argparse
import sys
import json
import traceback

# Relative imports for package modules
# from parsing import parse_text_to_json, format_json_to_solidity_struct
# from hashing import calculate_user_op_hash, eip191_hash_hex, eip191_hash_message, hex_to_bytes
# from signature import recover_signer
# from debug import run_debug_command
from .parsing import parse_text_to_json, format_json_to_solidity_struct
from .hashing import calculate_user_op_hash, eip191_hash_hex, eip191_hash_message, hex_to_bytes
from .signature import recover_signer
from .debug import run_debug_command

# --- CLI Definition --- 
def main():
    DEFAULT_ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" # v0.7

    parser = argparse.ArgumentParser(description="Parse UserOperation text, calculate hashes, verify signatures, and debug calls.")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Sub-command help')

    # --- `parse` subcommand --- 
    parser_parse = subparsers.add_parser('parse', help='Parse raw UserOperation text and output formatted JSON.')
    parser_parse.add_argument("raw_input", help="Raw UserOperation text data (like bundler debug output). Wrap in quotes.")

    # --- `userOpHash` subcommand --- 
    parser_hash = subparsers.add_parser('userOpHash', help='Calculate the EIP-4337 UserOperation hash.')
    parser_hash.add_argument("raw_input", help="Raw UserOperation text data. Wrap in quotes.")
    parser_hash.add_argument("-c", "--chainId", type=int, required=True, help="Chain ID for UserOpHash calculation.")
    parser_hash.add_argument("-e", "--entrypoint", default=DEFAULT_ENTRY_POINT, help=f"EntryPoint contract address (default: {DEFAULT_ENTRY_POINT}).")

    # --- `signer` subcommand --- 
    parser_signer = subparsers.add_parser('signer', help='Recover signer from signature or verify against an expected signer.')
    parser_signer.add_argument("raw_input", help="Raw UserOperation text data. Wrap in quotes.")
    parser_signer.add_argument("-c", "--chainId", type=int, required=True, help="Chain ID for UserOpHash calculation (needed for digest)." )
    parser_signer.add_argument("-e", "--entrypoint", default=DEFAULT_ENTRY_POINT, help=f"EntryPoint contract address (default: {DEFAULT_ENTRY_POINT}).")
    parser_signer.add_argument("-s", "--signer", nargs='?', const=True, default=None,
                             help="Perform signature recovery. If an address is provided, verify against that address. If flag is used alone, show all recovery results.")

    # --- `debug` subcommand --- 
    parser_debug = subparsers.add_parser('debug', help='Generate or execute `cast call --trace` for EntryPoint.handleOps.')
    parser_debug.add_argument("raw_input", help="Raw UserOperation text data. Wrap in quotes.")
    parser_debug.add_argument("--rpc-url", required=True, help="RPC URL for the cast command.")
    parser_debug.add_argument("--run", action='store_true', help="Execute the generated cast command instead of just printing it.")

    args = parser.parse_args()

    try:
        # --- Common Setup: Parse raw input to intermediate JSON --- 
        try:
            intermediate_json = parse_text_to_json(args.raw_input)
            user_op_intermediate_data = json.loads(intermediate_json)
        except json.JSONDecodeError as e:
            print(f"\nError: Could not parse the initial text input into valid JSON: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"\nError during initial parsing: {e}")
            sys.exit(1)

        # --- Command Dispatch --- 
        if args.command == 'parse':
            final_json = format_json_to_solidity_struct(intermediate_json)
            print("--- Formatted PackedUserOperation JSON ---")
            print(final_json)
        
        elif args.command == 'userOpHash':
            final_json = format_json_to_solidity_struct(intermediate_json)
            user_op_hash = calculate_user_op_hash(final_json, args.entrypoint, args.chainId)
            print("--- Calculated UserOpHash ---")
            print(user_op_hash)

        elif args.command == 'signer':
            expected_signer_address = None
            if isinstance(args.signer, str):
                expected_signer_address = args.signer
                if not expected_signer_address.startswith('0x') or len(expected_signer_address) != 42:
                    print(f"Error: Invalid format for --signer address: {expected_signer_address}")
                    sys.exit(1)
                try: bytes.fromhex(expected_signer_address[2:])
                except ValueError: 
                    print(f"Error: Invalid hex characters in --signer address: {expected_signer_address}")
                    sys.exit(1)

            final_json = format_json_to_solidity_struct(intermediate_json)
            user_op_hash = calculate_user_op_hash(final_json, args.entrypoint, args.chainId)
            user_op_hash_bytes = hex_to_bytes(user_op_hash)
            eip191_hash_of_hash_bytes_hex = eip191_hash_hex(user_op_hash)
            eip191_digest_bytes = hex_to_bytes(eip191_hash_of_hash_bytes_hex)
            eip191_hash_of_hash_string_hex = eip191_hash_message(user_op_hash)
            eip191_digest_string_bytes = hex_to_bytes(eip191_hash_of_hash_string_hex)

            if args.signer is None:
                print("\n--- Signature Recovery Skipped (no --signer flag provided) ---")
            else:
                print("\n--- Signature Recovery --- ")
                signature_hex = user_op_intermediate_data.get("signature")
                if not signature_hex or signature_hex == '0x':
                    print("No signature provided in input.")
                elif len(signature_hex) != 132:
                     print(f"Invalid signature length: {len(signature_hex)} chars (expected 132)")
                else:
                    recovered_from_userophash = recover_signer(user_op_hash_bytes, signature_hex)
                    recovered_from_eip191_bytes = recover_signer(eip191_digest_bytes, signature_hex)
                    recovered_from_eip191_string = recover_signer(eip191_digest_string_bytes, signature_hex)

                    if expected_signer_address:
                        print(f"Verifying signature against expected signer: {expected_signer_address}")
                        print(f"Signature provided: {signature_hex}")
                        match_found_signer = False
                        if recovered_from_userophash and recovered_from_userophash.lower() == expected_signer_address.lower():
                            print(f"  ✅ Matches signer for Digest 1 (UserOpHash Bytes)")
                            match_found_signer = True
                        if recovered_from_eip191_bytes and recovered_from_eip191_bytes.lower() == expected_signer_address.lower():
                            print(f"  ✅ Matches signer for Digest 2 (EIP-191 Bytes)")
                            match_found_signer = True
                        if recovered_from_eip191_string and recovered_from_eip191_string.lower() == expected_signer_address.lower():
                             print(f"  ✅ Matches signer for Digest 3 (EIP-191 String)")
                             match_found_signer = True
                        if not match_found_signer:
                            print(f"  ❌ Signature did NOT recover specified signer ({expected_signer_address}).")
                    else: # --signer flag only
                        sender_from_op = user_op_intermediate_data.get("sender")
                        if sender_from_op: print(f"Sender (from Op): {sender_from_op}")
                        print(f"Signature:        {signature_hex}")
                        print("\nShowing all recovery results:")
                        print("-"*20)
                        print(f"Digest 1 (UserOpHash): 0x{user_op_hash_bytes.hex()}")
                        print(f"  Recovered: {recovered_from_userophash or 'Failed'}")
                        print("-"*20)
                        print(f"Digest 2 (EIP-191 Bytes): 0x{eip191_digest_bytes.hex()}")
                        print(f"  Recovered: {recovered_from_eip191_bytes or 'Failed'}")
                        print("-"*20)
                        print(f"Digest 3 (EIP-191 String): 0x{eip191_digest_string_bytes.hex()}")
                        print(f"  Recovered: {recovered_from_eip191_string or 'Failed'}")
                        print("-"*20)
        
        elif args.command == 'debug':
            # Pass args and the already parsed intermediate data
            run_debug_command(args, user_op_intermediate_data)

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 