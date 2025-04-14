from eth_keys.exceptions import BadSignature
from eth_keys import keys

# Use relative import for shared utility
from .utils import hex_to_bytes

def recover_signer(digest_bytes: bytes, signature_hex: str) -> str | None:
    """Attempts to recover the signer's address from a digest and signature.

    Args:
        digest_bytes: The 32-byte hash (digest) that was signed.
        signature_hex: The signature as a 0x-prefixed hex string (65 bytes).

    Returns:
        The checksummed signer address as a string, or None if recovery fails.
    """
    if not signature_hex or signature_hex == '0x' or len(signature_hex) != 132:
        return None
    try:
        signature_bytes = hex_to_bytes(signature_hex)
        # if v is 27 or 28, set v to 0
        if signature_bytes[64] == 27 or signature_bytes[64] == 28:
            signature_bytes = signature_bytes[:64] + b'\x00'
        
        if len(digest_bytes) != 32:
            # print(f"Debug: Digest must be 32 bytes for recovery, got {len(digest_bytes)}.")
            return None

        signature = keys.Signature(signature_bytes=signature_bytes)
        public_key = signature.recover_public_key_from_msg_hash(digest_bytes)
        return public_key.to_checksum_address()
    except (BadSignature, ValueError, TypeError, Exception) as e: # Catch potential errors
        # print(f"Debug: Recovery failed for digest {digest_bytes.hex()} - {e}")
        return None 