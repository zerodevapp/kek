import argparse
import sys
import json
import traceback

# Relative imports for package modules
# from .parsing import parse_text_to_json, format_json_to_solidity_struct
from .parsing import detect_and_load_input, format_user_op_data # Updated imports
from .hashing import calculate_user_op_hash, eip191_hash_hex, eip191_hash_message, hex_to_bytes
from .signature import recover_signer
from .debug import run_debug_command

# --- CLI Definition ---
def main():
    DEFAULT_ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" # v0.7

    parser = argparse.ArgumentParser(description="Parse UserOperation text, calculate hashes, verify signatures, and debug calls.")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Sub-command help')

    # --- `parse` subcommand ---
    parser_parse = subparsers.add_parser('parse', help='Parse/normalize UserOp input and output formatted JSON.') # Updated help
    parser_parse.add_argument("raw_input", help="Raw UserOperation text, UserOp JSON, or PackedUserOp JSON. Wrap in quotes.")

    # --- `userOpHash` subcommand ---
    parser_hash = subparsers.add_parser('userOpHash', help='Calculate the EIP-4337 UserOperation hash from any input format.') # Updated help
    parser_hash.add_argument("raw_input", help="Raw UserOperation text, UserOp JSON, or PackedUserOp JSON. Wrap in quotes.")
    parser_hash.add_argument("-c", "--chainId", type=int, required=True, help="Chain ID for UserOpHash calculation.")
    parser_hash.add_argument("-e", "--entrypoint", default=DEFAULT_ENTRY_POINT, help=f"EntryPoint contract address (default: {DEFAULT_ENTRY_POINT}).")

    # --- `signer` subcommand ---
    parser_signer = subparsers.add_parser('signer', help='Recover/verify signer from any input format.') # Updated help
    parser_signer.add_argument("raw_input", help="Raw UserOperation text, UserOp JSON, or PackedUserOp JSON. Wrap in quotes.")
    parser_signer.add_argument("-c", "--chainId", type=int, required=True, help="Chain ID for UserOpHash calculation (needed for digest)." )
    parser_signer.add_argument("-e", "--entrypoint", default=DEFAULT_ENTRY_POINT, help=f"EntryPoint contract address (default: {DEFAULT_ENTRY_POINT}).")
    parser_signer.add_argument("-s", "--signer", nargs='?', const=True, default=None,
                             help="Perform signature recovery. If an address is provided, verify against that address. If flag is used alone, show all recovery results.")

    # --- `debug` subcommand ---
    parser_debug = subparsers.add_parser('debug', help='Generate `cast call --trace` command from any input format.') # Updated help
    parser_debug.add_argument("raw_input", help="Raw UserOperation text, UserOp JSON, or PackedUserOp JSON. Wrap in quotes.")
    parser_debug.add_argument("--rpc-url", required=True, help="RPC URL for the cast command.")
    # Removed --run flag

    args = parser.parse_args()

    try:
        # --- Common Setup: Detect input format and load into intermediate dict ---
        try:
            user_op_intermediate_data = detect_and_load_input(args.raw_input)
            if not user_op_intermediate_data:
                print("\nError: Could not parse input data.")
                sys.exit(1)
        except Exception as e:
            print(f"\nError processing input: {e}")
            traceback.print_exc()
            sys.exit(1)

        # --- Command Dispatch --- 
        if args.command == 'parse':
            # Action: Format the intermediate data and print
            final_json = format_user_op_data(user_op_intermediate_data)
            print("--- Formatted PackedUserOperation JSON ---")
            print(final_json)
        
        elif args.command == 'userOpHash':
            # Action: Format, calculate userOpHash
            final_json = format_user_op_data(user_op_intermediate_data)
            user_op_hash = calculate_user_op_hash(final_json, args.entrypoint, args.chainId)
            print("--- Calculated UserOpHash ---")
            print(user_op_hash)

        elif args.command == 'signer':
            # Action: Format, all hashes, recovery/verification
            expected_signer_address = None
            if isinstance(args.signer, str):
                # ... (validation remains the same) ...
                expected_signer_address = args.signer
                if not expected_signer_address.startswith('0x') or len(expected_signer_address) != 42:
                    print(f"Error: Invalid format for --signer address: {expected_signer_address}")
                    sys.exit(1)
                try: bytes.fromhex(expected_signer_address[2:])
                except ValueError: 
                    print(f"Error: Invalid hex characters in --signer address: {expected_signer_address}")
                    sys.exit(1)

            # Format the intermediate data first to ensure all fields are present/packed
            final_json = format_user_op_data(user_op_intermediate_data)
            
            # Calculate Hashes using the formatted JSON string
            user_op_hash = calculate_user_op_hash(final_json, args.entrypoint, args.chainId)
            user_op_hash_bytes = hex_to_bytes(user_op_hash)
            eip191_hash_of_hash_bytes_hex = eip191_hash_hex(user_op_hash)
            eip191_digest_bytes = hex_to_bytes(eip191_hash_of_hash_bytes_hex)
            eip191_hash_of_hash_string_hex = eip191_hash_message(user_op_hash)
            eip191_digest_string_bytes = hex_to_bytes(eip191_hash_of_hash_string_hex)

            # Use intermediate data *only* to get original signature if needed
            # Pass formatted final_json to functions needing struct fields
            signature_hex = user_op_intermediate_data.get("signature") 
            # Attempt case-insensitive lookup if direct fails
            if not signature_hex:
                 for k, v in user_op_intermediate_data.items():
                     if k.lower() == "signature":
                         signature_hex = v
                         break

            if args.signer is None:
                 print("\n--- Signature Recovery Skipped (no --signer flag provided) ---")
            else:
                print("\n--- Signature Recovery --- ")
                if not signature_hex or signature_hex == '0x':
                    print("No signature provided in input.")
                elif len(signature_hex) != 132:
                     print(f"Invalid signature length: {len(signature_hex)} chars (expected 132)")
                else:
                    recovered_from_userophash = recover_signer(user_op_hash_bytes, signature_hex)
                    recovered_from_eip191_bytes = recover_signer(eip191_digest_bytes, signature_hex)
                    recovered_from_eip191_string = recover_signer(eip191_digest_string_bytes, signature_hex)

                    if expected_signer_address:
                        # ... (Verification logic remains the same) ...
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
                        # ... (Display all results logic remains the same) ...
                        # Get sender from intermediate for context
                        sender_from_op = user_op_intermediate_data.get("sender")
                        if not sender_from_op:
                             for k, v in user_op_intermediate_data.items():
                                 if k.lower() == "sender":
                                     sender_from_op = v
                                     break
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
            # Pass args and the intermediate data (debug func will format)
            run_debug_command(args, user_op_intermediate_data)

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 