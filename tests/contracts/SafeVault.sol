// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Clean vault: checks-effects-interactions ordering, no reentrancy.
contract SafeVault {
    mapping(address => uint256) public balances;

    constructor() payable {}

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
