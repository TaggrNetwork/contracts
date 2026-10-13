// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.37;

import {Script, console} from "forge-std/Script.sol";
import {TaggrToken} from "../src/TaggrToken.sol";

/// @notice Deploys TaggrToken with the canister EOA as minter and controller.
/// @dev Run with:
///      TAGGR_MINTER=0x... TAGGR_CONTROLLER=0x... \
///        forge script script/Deploy.s.sol --rpc-url mainnet --broadcast --verify
contract Deploy is Script {
    error ZeroRoleAddress(string role);
    error RoleMismatch(string role);

    function run() external {
        address minter = vm.envAddress("TAGGR_MINTER");
        address controller = vm.envAddress("TAGGR_CONTROLLER");

        if (minter == address(0)) revert ZeroRoleAddress("TAGGR_MINTER");
        if (controller == address(0)) revert ZeroRoleAddress("TAGGR_CONTROLLER");

        vm.startBroadcast();
        TaggrToken token = new TaggrToken(minter, controller);
        vm.stopBroadcast();

        if (token.minter() != minter) revert RoleMismatch("minter");
        if (token.controller() != controller) revert RoleMismatch("controller");

        console.log("TaggrToken deployed at:", address(token));
        console.log("minter:", minter);
        console.log("controller:", controller);
    }
}
