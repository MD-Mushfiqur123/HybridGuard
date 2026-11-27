// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Classic reentrancy: external call happens before the balance reset (CEI violation).
contract ReentrancyVault {
    mapping(address => uint256) public balances;

    constructor() payable {}

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}
