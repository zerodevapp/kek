import unittest
import json

# Use relative imports for package modules
from .parsing import detect_and_load_input, format_user_op_data
from .hashing import calculate_user_op_hash

class TestUserOpHashing(unittest.TestCase):

    def test_user_op_hash_calculation(self):
        # --- PASTE YOUR INPUT DATA HERE --- 
        # Example using the raw text format:
        raw_input_data = """ 
          callData:                       0xe9ae5c53000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000034F892531A10B0060d3F0eCeeA2Da5dFbE7c41fE9c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
          callGasLimit:                   11192
          verificationGasLimit:           277415
          preVerificationGas:             55396
          sender:                         0x3976E2bA1a6343cCb3e6Fe25c72760302861D88f
          nonce:                          913479994650515257524606220465835134743662536739504695803980018773655552
          maxFeePerGas:                   0.000113318 gwei
          maxPriorityFeePerGas:           0.00011 gwei
          paymasterAndData:               0x2cc0c7981D846b9F2a16276556f6e8cb52BfB6330000000000000000000000000000729e00000000000000000000000000000000000000000000000067f7cafc27bfdbd1301e6b5dc8937121acb56431c9357443bb1e7f7ad2c5bb21b20125bc0aadbd26c7ae5575bd22c426ed9c201566db700a3b9498c52aba0da3dbbe3e1e1b
          signature:                      0x2f6fb903d0090b9491a32d2309f51983e3b53c3ec1f1dce74c80b2808b10c53c1917fac1d85eb16f687617aa5a594255f89781790ff78432e94e322320211a421b
          factory:                        0xd703aaE79538628d27099B8c4f621bE4CCd142d5
          factoryData:                    0xc5265d5d000000000000000000000000aac5d4240af87249b3f71bc8e4a2cae074a3e4190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001243c3b752b01845ADb2C711129d4f3966735eD98a9F09fC4cE570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014970aDa61CA296227aA84fF0B2E7b72875c4CC3580000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        """

        # --- PASTE YOUR EXPECTED HASH HERE --- 
        expected_hash = "0x26f47dffff62f7b59c17260885cc1d37b6dd6d0d5e45d14a4e34743fca56ac56"

        # --- SET YOUR CHAIN ID AND ENTRYPOINT HERE --- 
        chain_id = 84532 # Example: Base Sepolia
        entry_point = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" # v0.7

        # --- Test Logic --- 
        try:
            intermediate_data = detect_and_load_input(raw_input_data)
            formatted_json = format_user_op_data(intermediate_data)
            calculated_hash = calculate_user_op_hash(formatted_json, entry_point, chain_id)
            
            # Print intermediate steps for debugging
            print("\n--- Intermediate Data ---")
            print(json.dumps(intermediate_data, indent=2))
            print("\n--- Formatted JSON for Hashing ---")
            print(formatted_json)
            print("\n--- Calculated Hash --- ")
            print(calculated_hash)
            print("\n--- Expected Hash --- ")
            print(expected_hash)
            
            self.assertEqual(calculated_hash.lower(), expected_hash.lower(), 
                             f"Hash mismatch: Expected {expected_hash}, Got {calculated_hash}")
        except Exception as e:
            self.fail(f"Test failed with exception: {e}")

if __name__ == '__main__':
    unittest.main() 