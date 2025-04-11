def hex_to_bytes(hex_string: str) -> bytes:
    """Converts a hex string (with or without 0x prefix) to bytes."""
    if not isinstance(hex_string, str):
         raise TypeError(f"Input must be a string, got {type(hex_string)}")
    if hex_string.startswith('0x'):
        # Handle empty bytes case
        if len(hex_string) == 2:
            return b''
        return bytes.fromhex(hex_string[2:])
    # Handle empty bytes case for non-prefixed string
    if not hex_string:
        return b''
    try:
        return bytes.fromhex(hex_string)
    except ValueError as e:
        raise ValueError(f"Invalid hex string for hex_to_bytes: '{hex_string[:20]}...'") from e 