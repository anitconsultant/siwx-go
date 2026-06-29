// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Minimal ERC-1271 wallet owned by a single EOA (Safe-like 1-of-1).
contract TestWallet {
    address public owner;
    constructor(address _owner) { owner = _owner; }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        require(sig.length == 65, "bad len");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (ecrecover(hash, v, r, s) == owner) return 0x1626ba7e;
        return 0xffffffff;
    }
}

// CREATE2 factory: deploys TestWallet at a deterministic, counterfactual address.
contract TestFactory {
    event Deployed(address addr);
    function deploy(address owner, bytes32 salt) external returns (address addr) {
        addr = address(new TestWallet{salt: salt}(owner));
        emit Deployed(addr);
    }
    // Off-chain helpers to compute the counterfactual address.
    function initCodeHash(address owner) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(type(TestWallet).creationCode, abi.encode(owner)));
    }
}
