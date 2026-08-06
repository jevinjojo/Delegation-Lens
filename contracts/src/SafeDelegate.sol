// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// A minimal, reasonably-safe EIP-7702 delegate.
/// Runs in the authority EOA's context, so `address(this)` IS the EOA and the
/// EOA's own key is the ultimate authorizer.
contract SafeDelegate {
    // These live in the EOA's storage (7702 context).
    uint256 public execNonce; // action-level replay protection
    bool public initialized;
    address public owner;

    event Executed(address indexed target, uint256 value, bytes data);

    // Typehash for the signed action. Binds account, chain, nonce, deadline, and the call.
    bytes32 private constant EXECUTE_TYPEHASH =
        keccak256(
            "Execute(address account,uint256 chainId,uint256 nonce,uint256 deadline,address target,uint256 value,bytes data)"
        );

    // PROTECTION 1: guarded initializer — only the account itself, only once.
    function initialize(address _owner) external {
        require(msg.sender == address(this), "only self"); // account-gated
        require(!initialized, "already initialized"); // one-time
        initialized = true;
        owner = _owner;
    }

    // PROTECTION 2/3/4: authenticated + replay-protected + chain/account-bound execution.
    // A relayer submits this; authority comes from the EOA's signature over the exact action.
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bytes memory) {
        require(block.timestamp <= deadline, "expired"); // deadline bound

        uint256 currentNonce = execNonce;
        bytes32 digest = keccak256(
            abi.encode(
                EXECUTE_TYPEHASH,
                address(this), // bound to THIS account
                block.chainid, // bound to THIS chain
                currentNonce, // bound to a single use (replay protection)
                deadline,
                target,
                value,
                keccak256(data) // bound to the exact calldata
            )
        );

        address signer = ecrecover(digest, v, r, s);
        require(
            signer != address(0) && signer == address(this),
            "bad signature"
        );

        execNonce = currentNonce + 1; // consume nonce BEFORE the call
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        emit Executed(target, value, data);
        return ret;
    }

    receive() external payable {}
}
