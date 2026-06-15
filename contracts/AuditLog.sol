// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuditLog {
    address public owner;
    
    event ChainAnchored(bytes32 indexed rootHash, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    function anchorChain(bytes32 rootHash) external {
        require(msg.sender == owner, "Only owner can anchor");
        emit ChainAnchored(rootHash, block.timestamp);
    }
}
