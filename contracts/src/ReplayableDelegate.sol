// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ReplayableDelegate {
    // BUG: the signed digest omits nonce, deadline, chainId, and account binding.
    // Even though it checks the account's signature, the SAME signature can be
    // replayed forever (and across chains/accounts).
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encode(target, value, keccak256(data))); // no nonce/deadline/chainId/account
        address signer = ecrecover(digest, v, r, s);
        require(signer == address(this), "bad signature");
        (bool ok, ) = target.call{value: value}(data);
        require(ok, "call failed");
    }

    receive() external payable {}
}
