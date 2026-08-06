// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract OpenExecuteDelegate {
    // BUG: fully public execute with ZERO authentication. Anyone who calls the
    // delegated EOA can make it send its ETH / call any contract as itself.
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    receive() external payable {}
}
