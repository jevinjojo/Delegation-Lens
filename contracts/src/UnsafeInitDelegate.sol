// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract UnsafeInitDelegate {
    bool public initialized;
    address public owner;

    // BUG: no `msg.sender == address(this)` guard. Anyone can call the delegated
    // EOA's initialize() and seize ownership (front-run / re-initialize).
    function initialize(address _owner) external {
        owner = _owner;
        initialized = true;
    }

    // A privileged action gated only by the (hijackable) owner.
    function sweep(address to) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
