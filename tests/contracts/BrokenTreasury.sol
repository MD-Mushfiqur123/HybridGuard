// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Access-control flaw: anyone can trigger the payout and burn the treasury.
contract BrokenTreasury {
    address public owner;
    uint256 public payoutAmount = 1 ether;

    constructor() payable {
        owner = msg.sender;
    }

    function payout(address payable recipient) external {
        (bool ok, ) = recipient.call{value: payoutAmount}("");
        require(ok, "payout failed");
    }

    function deposit() external payable {}
}
