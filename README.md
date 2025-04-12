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

# Parse raw UserOp text to formatted JSON
aa-script parse "<raw_user_op_text>"

# Calculate UserOp hash
aa-script userOpHash "<raw_user_op_text>" --chainId <id> [--entrypoint <addr>]

# Recover signer (show all attempts)
aa-script signer "<raw_user_op_text>" --chainId <id> --signer [--entrypoint <addr>]

# Verify signer against a specific address
aa-script signer "<raw_user_op_text>" --chainId <id> --signer <expected_addr> [--entrypoint <addr>]

# Generate debug cast call command
aa-script debug "<raw_user_op_text>" --rpc-url <url>

# Generate AND execute debug cast call command
aa-script debug "<raw_user_op_text>" --rpc-url <url> --run

# or pipe to shell
aa-script debug "<raw_user_op_text>" --rpc-url <url> | sh
```

**Note:** Wrap multi-line raw UserOperation text in quotes (`"..."`). 

- [ ] Add support for getting userOp json or packedUserOp as input
- [ ] Use entrypoint simulation contract to get the detailed trace