//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {MinimalAccount} from "../src/ethereum/MinimalAccount.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {console2} from "forge-std/console2.sol";

contract DeployMinimal is Script {
    function run() external {
        deployMinimalAccount();
    }

    function deployMinimalAccount()
        public
        returns (HelperConfig, MinimalAccount)
    {
        HelperConfig helperConfig = new HelperConfig();
        HelperConfig.NetworkConfig memory config = helperConfig.getConfig();
        address sender = config.account[0];
        console2.log("Sender: %s", sender);
        vm.startBroadcast(sender);
        MinimalAccount minimalAccount = new MinimalAccount(
            config.account[1]
        );
        vm.stopBroadcast();
        return (helperConfig, minimalAccount);
    }
}