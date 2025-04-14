# AA Helper

A CLI tool to parse, hash, verify signatures, and debug EIP-4337 UserOperations.

## Installation

```bash
# Install in editable mode
pip install -e .
```

## Usage

The tool provides several commands:

```bash
# Get help
aa-script --help

# Format input (raw text, UserOp JSON, PackedUserOp JSON) to specified output JSON
aa-script format "<input_data>" [--output <packed|userop>] # Default output is packed

# Calculate UserOp hash from any input format
aa-script userOpHash "<input_data>" --chainId <id> [--entrypoint <addr>]

# Recover signer (show all attempts) from any input format
aa-script signer "<input_data>" --chainId <id> --signer [--entrypoint <addr>]

# Verify signer against a specific address from any input format
aa-script signer "<input_data>" --chainId <id> --signer <expected_addr> [--entrypoint <addr>]

# Generate debug cast call command from any input format
aa-script debug "<input_data>" --rpc-url <url>

# Generate AND execute debug cast call command
aa-script debug "<raw_user_op_text>" --rpc-url <url> --run

# or pipe to shell
aa-script debug "<raw_user_op_text>" --rpc-url <url> | sh
```

**Note:** Wrap multi-line raw UserOperation text in quotes (`"..."`). 

- [ ] Add support for getting userOp json or packedUserOp as input
- [ ] Use entrypoint simulation contract to get the detailed trace