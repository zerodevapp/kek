import unittest
import json
from click.testing import CliRunner

# Assuming your CLI entry point is defined in src.kek.cli
# Adjust the import path if necessary
from kek.cli import cli

# --- Test Data ---
RAW_TEXT_INPUT = """
    callData:                       0xe9ae5c53000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000034F892531A10B0060d3F0eCeeA2Da5dFbE7c41fE9c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    callGasLimit:                   11192
    factory:                        0xd703aaE79538628d27099B8c4f621bE4CCd142d5
    factoryData:                    0xc5265d5d000000000000000000000000aac5d4240af87249b3f71bc8e4a2cae074a3e4190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001243c3b752b01845ADb2C711129d4f3966735eD98a9F09fC4cE570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014970aDa61CA296227aA84fF0B2E7b72875c4CC3580000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    maxFeePerGas:                   0.000113318 gwei
    maxPriorityFeePerGas:           0.00011 gwei
    nonce:                          913479994650515257524606220465835134743662536739504695803980018773655552
    paymaster:                      0x2cc0c7981D846b9F2a16276556f6e8cb52BfB633
    paymasterData:                  0x000000000000000067f7cafc27bfdbd1301e6b5dc8937121acb56431c9357443bb1e7f7ad2c5bb21b20125bc0aadbd26c7ae5575bd22c426ed9c201566db700a3b9498c52aba0da3dbbe3e1e1b
    paymasterPostOpGasLimit:        0
    paymasterVerificationGasLimit:  29342
    preVerificationGas:             55396
    sender:                         0x3976E2bA1a6343cCb3e6Fe25c72760302861D88f
    signature:                      0x2f6fb903d0090b9491a32d2309f51983e3b53c3ec1f1dce74c80b2808b10c53c1917fac1d85eb16f687617aa5a594255f89781790ff78432e94e322320211a421b
    verificationGasLimit:           277415
"""

JSON_INPUT = """
{
  "sender": "0x3976E2bA1a6343cCb3e6Fe25c72760302861D88f",
  "nonce": "913479994650515257524606220465835134743662536739504695803980018773655552",
  "initCode": "0xd703aaE79538628d27099B8c4f621bE4CCd142d5c5265d5d000000000000000000000000aac5d4240af87249b3f71bc8e4a2cae074a3e4190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001243c3b752b01845ADb2C711129d4f3966735eD98a9F09fC4cE570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014970aDa61CA296227aA84fF0B2E7b72875c4CC3580000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "callData": "0xe9ae5c53000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000034F892531A10B0060d3F0eCeeA2Da5dFbE7c41fE9c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "callGasLimit": "11192",
  "verificationGasLimit": "277415",
  "preVerificationGas": "55396",
  "maxFeePerGas": "113318",
  "maxPriorityFeePerGas": "110000",
  "paymasterAndData": "0x2cc0c7981D846b9F2a16276556f6e8cb52BfB6330000000000000000000000000000729e00000000000000000000000000000000000000000000000067f7cafc27bfdbd1301e6b5dc8937121acb56431c9357443bb1e7f7ad2c5bb21b20125bc0aadbd26c7ae5575bd22c426ed9c201566db700a3b9498c52aba0da3dbbe3e1e1b",
  "signature": "0x2f6fb903d0090b9491a32d2309f51983e3b53c3ec1f1dce74c80b2808b10c53c1917fac1d85eb16f687617aa5a594255f89781790ff78432e94e322320211a421b"
}
"""

CHAIN_ID = 84532
ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" # v0.7
RPC_URL = "https://sepolia.base.org"
EXPECTED_SENDER = "0x3976E2bA1a6343cCb3e6Fe25c72760302861D88f"
# Use the hash calculated by the fixed code
EXPECTED_HASH = "0x26f47dffff62f7b59c17260885cc1d37b6dd6d0d5e45d14a4e34743fca56ac56"

# Expected JSON outputs (can be derived from format.py logic or running commands manually)
EXPECTED_PACKED_JSON = """{
  "sender": "0x3976E2bA1a6343cCb3e6Fe25c72760302861D88f",
  "nonce": "913479994650515257524606220465835134743662536739504695803980018773655552",
  "initCode": "0xd703aaE79538628d27099B8c4f621bE4CCd142d5c5265d5d000000000000000000000000aac5d4240af87249b3f71bc8e4a2cae074a3e4190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001243c3b752b01845ADb2C711129d4f3966735eD98a9F09fC4cE570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014970aDa61CA296227aA84fF0B2E7b72875c4CC3580000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "callData": "0xe9ae5c53000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000034F892531A10B0060d3F0eCeeA2Da5dFbE7c41fE9c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "accountGasLimits": "0x00000000000000000000000000043ba700000000000000000000000000002bb8",
  "preVerificationGas": "55396",
  "gasFees": "0x0000000000000000000000000001adb00000000000000000000000000001baa6",
  "paymasterAndData": "0x2cc0c7981D846b9F2a16276556f6e8cb52BfB6330000000000000000000000000000729e00000000000000000000000000000000000000000000000067f7cafc27bfdbd1301e6b5dc8937121acb56431c9357443bb1e7f7ad2c5bb21b20125bc0aadbd26c7ae5575bd22c426ed9c201566db700a3b9498c52aba0da3dbbe3e1e1b",
  "signature": "0x2f6fb903d0090b9491a32d2309f51983e3b53c3ec1f1dce74c80b2808b10c53c1917fac1d85eb16f687617aa5a594255f89781790ff78432e94e322320211a421b"
}"""

EXPECTED_USEROP_JSON = """{
  "sender": "0x3976E2bA1a6343cCb3e6Fe25c72760302861D88f",
  "nonce": "0x845adb2c711129d4f3966735ed98a9f09fc4ce5700040000000000000000",
  "factory": "0xd703aaE79538628d27099B8c4f621bE4CCd142d5",
  "factoryData": "0xc5265d5d000000000000000000000000aac5d4240af87249b3f71bc8e4a2cae074a3e4190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001243c3b752b01845ADb2C711129d4f3966735eD98a9F09fC4cE570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014970aDa61CA296227aA84fF0B2E7b72875c4CC3580000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "callData": "0xe9ae5c53000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000034F892531A10B0060d3F0eCeeA2Da5dFbE7c41fE9c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "callGasLimit": "0x2bb8",
  "verificationGasLimit": "0x43ba7",
  "preVerificationGas": "0xd864",
  "maxFeePerGas": "0x1baa6",
  "maxPriorityFeePerGas": "0x1adb0",
  "paymaster": "0x2cc0c7981D846b9F2a16276556f6e8cb52BfB633",
  "paymasterVerificationGasLimit": "0x729e",
  "paymasterPostOpGasLimit": "0x0",
  "paymasterData": "0x000000000000000067f7cafc27bfdbd1301e6b5dc8937121acb56431c9357443bb1e7f7ad2c5bb21b20125bc0aadbd26c7ae5575bd22c426ed9c201566db700a3b9498c52aba0da3dbbe3e1e1b",
  "signature": "0x2f6fb903d0090b9491a32d2309f51983e3b53c3ec1f1dce74c80b2808b10c53c1917fac1d85eb16f687617aa5a594255f89781790ff78432e94e322320211a421b"
}"""

EXPECTED_SIGNER = "0x970ada61ca296227aa84ff0b2e7b72875c4cc358"

class TestKekCli(unittest.TestCase):

    def assertSuccess(self, result):
        self.assertEqual(result.exit_code, 0, f"CLI command failed: {result.output}")

    def assertOutputContains(self, result, expected_substring):
        self.assertIn(expected_substring, result.output, 
                      f"Output missing '{expected_substring}':\n{result.output}")

    def assertJsonOutputEqual(self, output_str, expected_json_str):
        try:
            output_json = json.loads(output_str)
            expected_json = json.loads(expected_json_str)
            self.assertDictEqual(output_json, expected_json,
                                 f"JSON output mismatch:\nExpected:\n{expected_json_str}\nGot:\n{output_str}")
        except json.JSONDecodeError:
            self.fail(f"Output is not valid JSON:\n{output_str}")

    # --- Format Tests ---

    def test_format_packed_raw(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['format', RAW_TEXT_INPUT, '--output', 'packed'])
        self.assertSuccess(result)
        self.assertOutputContains(result, "--- Formatted PackedUserOperation JSON ---")
        # Extract JSON part after the header
        json_output = result.output.split("--- Formatted PackedUserOperation JSON ---")[-1].strip()
        self.assertJsonOutputEqual(json_output, EXPECTED_PACKED_JSON)

    def test_format_packed_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['format', JSON_INPUT, '--output', 'packed'])
        self.assertSuccess(result)
        self.assertOutputContains(result, "--- Formatted PackedUserOperation JSON ---")
        json_output = result.output.split("--- Formatted PackedUserOperation JSON ---")[-1].strip()
        self.assertJsonOutputEqual(json_output, EXPECTED_PACKED_JSON)

    def test_format_userop_raw(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['format', RAW_TEXT_INPUT, '--output', 'userop'])
        self.assertSuccess(result)
        self.assertOutputContains(result, "--- Standard UserOperation JSON ---")
        json_output = result.output.split("--- Standard UserOperation JSON ---")[-1].strip()
        self.assertJsonOutputEqual(json_output, EXPECTED_USEROP_JSON)

    def test_format_userop_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['format', JSON_INPUT, '--output', 'userop'])
        self.assertSuccess(result)
        self.assertOutputContains(result, "--- Standard UserOperation JSON ---")
        json_output = result.output.split("--- Standard UserOperation JSON ---")[-1].strip()
        # check as json object and check all keys are present by iterating over expected keys
        json_output_obj = json.loads(json_output)
        for key in json.loads(EXPECTED_USEROP_JSON).keys():
            self.assertIn(key, json_output_obj)
        # check all values are present by iterating over expected values
        for key, value in json.loads(EXPECTED_USEROP_JSON).items():
            self.assertEqual(json_output_obj[key], value)

    # --- userOpHash Tests ---

    def test_userophash_raw(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['userOpHash', RAW_TEXT_INPUT, '--chainId', str(CHAIN_ID)])
        self.assertSuccess(result)
        self.assertOutputContains(result, "--- Calculated UserOpHash ---")
        self.assertOutputContains(result, EXPECTED_HASH)

    def test_userophash_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['userOpHash', JSON_INPUT, '--chainId', str(CHAIN_ID)])
        self.assertSuccess(result)
        self.assertOutputContains(result, "--- Calculated UserOpHash ---")
        self.assertOutputContains(result, EXPECTED_HASH)

    # # --- Signer Tests ---

    def test_signer_recover_raw(self):
        runner = CliRunner()
        # Use --signer flag without address to trigger recovery mode
        result = runner.invoke(cli, ['signer', RAW_TEXT_INPUT, '--chainId', str(CHAIN_ID), '--entrypoint', ENTRY_POINT, '--signer', EXPECTED_SIGNER])
        self.assertSuccess(result)
        self.assertOutputContains(result, "--- Signature Recovery ---")
        self.assertOutputContains(result, f"Verifying signature against expected signer: {EXPECTED_SIGNER}")
        self.assertOutputContains(result, "✅ Matches signer")

    def test_signer_verify_correct_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['signer', JSON_INPUT, '--chainId', str(CHAIN_ID), '--entrypoint', ENTRY_POINT, '--signer', EXPECTED_SIGNER])
        self.assertSuccess(result)
        self.assertOutputContains(result, f"Verifying signature against expected signer: {EXPECTED_SIGNER}")
        self.assertOutputContains(result, "✅ Matches signer")

    def test_signer_verify_incorrect_raw(self):
        runner = CliRunner()
        incorrect_signer = "0x1111111111111111111111111111111111111111"
        result = runner.invoke(cli, ['signer', RAW_TEXT_INPUT, '--chainId', str(CHAIN_ID), '--entrypoint', ENTRY_POINT, '--signer', incorrect_signer])
        self.assertSuccess(result) # Command should still succeed even if verification fails
        self.assertOutputContains(result, f"Verifying signature against expected signer: {incorrect_signer}")
        self.assertOutputContains(result, f"❌ Signature did NOT recover specified signer ({incorrect_signer})")

    # --- Debug Test ---

    def test_debug_raw(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['debug', RAW_TEXT_INPUT, '--rpc-url', RPC_URL])
        self.assertSuccess(result)
        self.assertOutputContains(result, f"cast call {ENTRY_POINT}")
        self.assertOutputContains(result, "--rpc-url https://sepolia.base.org")
        self.assertOutputContains(result, "--trace")
        # Check for the handleOps selector
        self.assertOutputContains(result, "0x765e827f") 

    def test_debug_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['debug', JSON_INPUT, '--rpc-url', RPC_URL])
        self.assertSuccess(result)
        self.assertOutputContains(result, f"cast call {ENTRY_POINT}")
        self.assertOutputContains(result, "--rpc-url https://sepolia.base.org")
        self.assertOutputContains(result, "--trace")
        self.assertOutputContains(result, "0x765e827f") 


if __name__ == '__main__':
    unittest.main()
