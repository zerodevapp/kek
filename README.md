# KEK: Kernel Examination Kit

A CLI tool to parse, hash, verify signatures, and debug EIP-4337 UserOperations, designed for use with Kernel.

## Installation

```bash
# Navigate to the project directory (containing pyproject.toml)
cd <project-directory>
# Install in editable mode (use a virtual environment)
pip install -e .
```

## Usage

The tool provides several commands:

```bash
# Get help
kek --help

# Format input (raw text, UserOp JSON, PackedUserOp JSON) to specified output JSON
kek format "<input_data>" [--output <packed|userop>] # Default output is packed

# Calculate UserOp hash from any input format
kek userOpHash "<input_data>" --chainId <id> [--entrypoint <addr>]

# Recover signer (show all attempts) from any input format
kek signer "<input_data>" --chainId <id> --signer [--entrypoint <addr>]

# Verify signer against a specific address from any input format
kek signer "<input_data>" --chainId <id> --signer <expected_addr> [--entrypoint <addr>]

# Generate debug cast call command from any input format (DEFAULT: prints command)
kek debug "<input_data>" --rpc-url <url>

# Generate AND execute debug cast call command
kek debug "<input_data>" --rpc-url <url> | sh
```

**Note:** Wrap multi-line raw UserOperation text in quotes (`"..."`). 

- [ ] Use entrypoint simulation contract to get the detailed trace