// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Arithmetic flaw inside an unchecked block: balance accounting can underflow.
contract UncheckedPool {
    mapping(address => uint256) public balances;

    constructor() payable {}

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function adjustBalance(address user, uint256 delta) external {
        unchecked {
            balances[user] = balances[user] - delta;
        }
    }
}
