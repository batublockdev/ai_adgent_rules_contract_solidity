//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {
    EntryPoint
} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {console2} from "forge-std/console2.sol";
import {ERC20Mock} from "test/mock/ERC20Mock.sol";
import {MockV3Aggregator} from "../test/mock/MockV3Aggregator.sol";

contract HelperConfig is Script {
    error HelperConig__InvalidChainId();

    struct NetworkConfig {
        address entryPoint;
        address usd;
        address wbtc;
        address[2] account;
        address priceFeed;       // CELO/USD
        address brlUsdPriceFeed; // BRL/USD
        uint8 tokenDecimals;
    }
    uint8 public constant DECIMALS = 8;
    int256 public constant ETH_USD_PRICE = 2000e8;
    uint256 constant ETH_SEPOLIA_CHAIN_ID = 155111;
    uint256 constant ZKSYNC_SEPOLIA_CHAIN_ID = 300;
    uint256 constant LOCAL_CHAIN_ID = 31337;
    uint256 constant CELO_MAINNET_CHAIN_ID = 42220;
    address constant BURNER_WALLET = 0x27fe1ac5A0eBD0c969C51B1f040ad704C4aB20A0;
    address constant ANVIL_DEFAULT_ACCOUNT =
        0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address constant ANVIL_DEFAULT_ACCOUNT2 =
        0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    NetworkConfig public localNetworkConfig =
        NetworkConfig({
            entryPoint: address(0),
            usd: address(0),
            wbtc: address(0),
            account: [address(0), address(0)],
            priceFeed: address(0),
            brlUsdPriceFeed: address(0),
            tokenDecimals: 18
        });
    mapping(uint256 chainId => NetworkConfig) networkCOnfigs;

    constructor() {
        networkCOnfigs[ETH_SEPOLIA_CHAIN_ID] = getEthSepoliaConfig();
        networkCOnfigs[CELO_MAINNET_CHAIN_ID] = getCeloConfig();
    }

    function getConfig() public returns (NetworkConfig memory) {
        console2.log("GetConfig");
        return getConfigByChainId(block.chainid);
    }

    function getConfigByChainId(
        uint256 chainId
    ) public returns (NetworkConfig memory) {
        if (chainId == LOCAL_CHAIN_ID) {
            console2.log("Local chain id");
            return getAnvilConfig();
        } else if (networkCOnfigs[chainId].entryPoint != address(0)) {
            return networkCOnfigs[chainId];
        } else {
            revert HelperConig__InvalidChainId();
        }
    }

    function getEthSepoliaConfig() public pure returns (NetworkConfig memory) {
        return
            NetworkConfig({
                entryPoint: 0x433709009B8330FDa32311DF1C2AFA402eD8D009,
                usd: address(0),
                wbtc: address(0),
                account: [address(0), address(0)],
                priceFeed: address(0),
                brlUsdPriceFeed: address(0),
                tokenDecimals: 6
            });
    }

    function getZkSyncSepoliaConfig()
        public
        pure
        returns (NetworkConfig memory)
    {
        return
            NetworkConfig({
                entryPoint: address(0),
                usd: address(0),
                wbtc: address(0),
                account: [address(0), address(0)],
                priceFeed: address(0),
                brlUsdPriceFeed: address(0),
                tokenDecimals: 6
            });
    }
    function getCeloConfig() public pure returns (NetworkConfig memory) {
        return
            NetworkConfig({
                entryPoint: 0x433709009B8330FDa32311DF1C2AFA402eD8D009,
                usd: 0xD76f5Faf6888e24D9F04Bf92a0c8B921FE4390e0, // wBRL
                wbtc: 0x471EcE3750Da237f93B8E339c536989b8978a438, // CELO
                account: [
                    0x5CE3bA750E63Bd990876Ed504cE2B2A6f21DA06f,
                    0xf43ea1700E117e9c456690514Db9C5b1405EC5E5
                ],
                priceFeed: 0x0568fD19986748cEfF3301e55c0eb1E729E0Ab7e, // Chainlink CELO/USD
                brlUsdPriceFeed: 0xe8EcaF727080968Ed5F6DBB595B91e50eEb9F8B3, // Chainlink BRL/USD
                tokenDecimals: 18 // wBRL tiene 18 decimales
            });
    }

    function getAnvilConfig() public returns (NetworkConfig memory) {
        if (localNetworkConfig.entryPoint != address(0)) {
            console2.log("xxx");
            return localNetworkConfig;
        }
        console2.log("Deploying mocks...");
        vm.startBroadcast(ANVIL_DEFAULT_ACCOUNT);
        EntryPoint entryPoint = new EntryPoint();
        ERC20Mock usdc = new ERC20Mock(
            "USD Coin",
            "USDC",
            100,
            address(entryPoint)
        );
        MockV3Aggregator ethUsdPriceFeed = new MockV3Aggregator(
            DECIMALS,
            ETH_USD_PRICE
        );
        vm.stopBroadcast();
        console2.log("Mocks deployed!");

        // Mock BRL/USD feed para local
        MockV3Aggregator brlUsdPriceFeed = new MockV3Aggregator(
            DECIMALS,
            5e8 // 5.00 BRL/USD
        );

        localNetworkConfig = NetworkConfig({
            entryPoint: address(entryPoint),
            usd: address(usdc),
            wbtc: address(0),
            account: [ANVIL_DEFAULT_ACCOUNT, ANVIL_DEFAULT_ACCOUNT2],
            priceFeed: address(ethUsdPriceFeed),
            brlUsdPriceFeed: address(brlUsdPriceFeed),
            tokenDecimals: 18 // ERC20Mock tiene 18 decimales
        });

        return localNetworkConfig;
    }
}