// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {MinimalAccount} from "src/ethereum/MinimalAccount.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    MessageHashUtils
} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @notice Tests que requieren fork de Celo mainnet.
///         Correr con:
///         forge test --match-contract MinimalAccountCeloTest \
///           --fork-url https://celo-mainnet.core.chainstack.com/6637f2f34a100899d962161848ac1912 \
///           --chain-id 42220 -vvv
contract MinimalAccountCeloTest is Test {
    using MessageHashUtils for bytes32;

    MinimalAccount minimalAccount;

    // Anvil default accounts
    address constant OWNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address constant ADGENT = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    uint256 constant OWNER_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant ADGENT_KEY =
        0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    // Celo mainnet tokens
    address constant USDT = 0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e;
    address constant USDC = 0xcebA9300f2b948710d2653dD7B07f33A8B32118C;
    address constant WBTC = 0x8aC2901Dd8A1F17a1A4768A6bA4C3751e3995B2D;
    address constant WETH = 0xD221812de1BD094f35587EE8E174B07B6167D9Af;
    address constant WBRL = 0xD76f5Faf6888e24D9F04Bf92a0c8B921FE4390e0;
    address constant AAVE_POOL = 0x3E59A31363E2ad014dcbc521c4a0d5757d9f3402;

    // Celo mainnet contracts
    address constant UNIVERSAL_ROUTER =
        0xe2023F3FA515cF070e07fD9d51c1d236e07843f4;
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    // USDT holder en Celo mainnet
    address constant USDT_HOLDER = 0x610982a5D0d7E77F61b0B8523b10Bb0092007D45;

    // Selectores hardcodeados en el contrato
    bytes4 constant APPROVE_SELECTOR = 0x095ea7b3;
    bytes4 constant PERMIT2_PERMIT_SELECTOR = 0x87517c45;
    bytes4 constant UNIVERSAL_EXECUTE_SELECTOR = 0x3593564c;

    // Selectores Aave V3
    bytes4 constant SUPPLY_SELECTOR = 0x617ba037;
    bytes4 constant WITHDRAW_SELECTOR = 0x69328dec;
    bytes4 constant BORROW_SELECTOR = 0xa415bcad;
    bytes4 constant REPAY_SELECTOR = 0x573ade81;

    // Amounts
    uint256 constant SWAP_AMOUNT_USDT = 10 * 1e6; // USDT 6 decimals
    uint256 constant SWAP_AMOUNT_WBRL = 10 * 1e18; // wBRL 18 decimals
    uint256 constant BORROW_AMOUNT_WETH = 0.0003 ether; // 300000000000000
    uint256 constant REPAY_AMOUNT_WETH = 0.0002 ether; // 200000000000000
    uint256 constant WITHDRAW_AMOUNT_USDT = 1 * 1e6; // 1 USDT

    function setUp() public {
        vm.prank(OWNER);
        minimalAccount = new MinimalAccount(ADGENT);
    }

    // ============================================================
    // HELPERS
    // ============================================================

    function _signExecution(
        address target,
        uint256 value,
        bytes memory data,
        uint256 _nonce,
        uint256 chainId,
        uint256 privateKey
    ) internal pure returns (bytes memory) {
        bytes32 hash = keccak256(
            abi.encode(target, value, keccak256(data), _nonce, chainId)
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function _executeAsOwner(
        address target,
        uint256 value,
        bytes memory data
    ) internal {
        bytes memory sig = _signExecution(
            target,
            value,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );
        vm.prank(address(0xBEEF));
        minimalAccount.execute(target, value, data, sig);
    }

    function _executeAsAdgent(
        address target,
        uint256 value,
        bytes memory data
    ) internal {
        bytes memory sig = _signExecution(
            target,
            value,
            data,
            minimalAccount.nonce(),
            block.chainid,
            ADGENT_KEY
        );
        vm.prank(address(0xBEEF));
        minimalAccount.execute(target, value, data, sig);
    }

    /// @dev Setup completo de approves + permit2 para un token
    function _setupApproves(address token, bool useAdgent) internal {
        bytes memory approveRouterData = abi.encodeWithSelector(
            APPROVE_SELECTOR,
            UNIVERSAL_ROUTER,
            type(uint256).max
        );
        bytes memory approvePermit2Data = abi.encodeWithSelector(
            APPROVE_SELECTOR,
            PERMIT2,
            type(uint256).max
        );
        bytes memory permit2ApproveData = abi.encodeWithSelector(
            PERMIT2_PERMIT_SELECTOR,
            token,
            UNIVERSAL_ROUTER,
            type(uint160).max,
            type(uint48).max
        );

        if (useAdgent) {
            _executeAsAdgent(token, 0, approveRouterData);
            _executeAsAdgent(token, 0, approvePermit2Data);
            _executeAsAdgent(PERMIT2, 0, permit2ApproveData);
        } else {
            _executeAsOwner(token, 0, approveRouterData);
            _executeAsOwner(token, 0, approvePermit2Data);
            _executeAsOwner(PERMIT2, 0, permit2ApproveData);
        }
    }

    /// @dev Construye y ejecuta un swap via Universal Router
    function _executeSwap(
        address tokenIn,
        uint256 amountIn,
        bytes memory path,
        bool useAdgent
    ) internal {
        bytes memory commands = abi.encodePacked(bytes1(0x00)); // V3_SWAP_EXACT_IN
        bytes memory swapInput = abi.encode(
            address(minimalAccount), // recipient
            amountIn, // amountIn
            uint256(1), // amountOutMin
            path, // path
            true, // payerIsUser
            new bytes(0) // extra
        );
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = swapInput;
        bytes memory swapData = abi.encodeWithSelector(
            UNIVERSAL_EXECUTE_SELECTOR,
            commands,
            inputs,
            block.timestamp + 60
        );

        if (useAdgent) {
            _executeAsAdgent(UNIVERSAL_ROUTER, 0, swapData);
        } else {
            _executeAsOwner(UNIVERSAL_ROUTER, 0, swapData);
        }
    }

    /// @dev Supply USDT a Aave como colateral (helper para tests de borrow/withdraw)
    function _supplyUSDTtoAave(bool useAdgent) internal {
        IERC20 usdt = IERC20(USDT);

        vm.prank(USDT_HOLDER);
        usdt.transfer(address(minimalAccount), SWAP_AMOUNT_USDT);

        // Approve USDT al Aave Pool
        bytes memory approveData = abi.encodeWithSelector(
            APPROVE_SELECTOR,
            AAVE_POOL,
            type(uint256).max
        );
        if (useAdgent) {
            _executeAsAdgent(USDT, 0, approveData);
        } else {
            _executeAsOwner(USDT, 0, approveData);
        }

        // Supply USDT
        bytes memory supplyData = abi.encodeWithSelector(
            SUPPLY_SELECTOR,
            USDT,
            SWAP_AMOUNT_USDT,
            address(minimalAccount),
            uint16(0)
        );
        if (useAdgent) {
            _executeAsAdgent(AAVE_POOL, 0, supplyData);
        } else {
            _executeAsOwner(AAVE_POOL, 0, supplyData);
        }
    }

    // ============================================================
    // VERIFY: Constructor pre-configuró todo
    // ============================================================

    function testConstructor_PreConfiguredTargets() public view {
        assertTrue(
            minimalAccount.isAllowedTarget(UNIVERSAL_ROUTER),
            "Universal Router"
        );
        assertTrue(minimalAccount.isAllowedTarget(PERMIT2), "Permit2");
        assertTrue(minimalAccount.isAllowedTarget(USDT), "USDT");
        assertTrue(minimalAccount.isAllowedTarget(USDC), "USDC");
        assertTrue(minimalAccount.isAllowedTarget(WBTC), "WBTC");
        assertTrue(minimalAccount.isAllowedTarget(WBRL), "WBRL");
    }

    function testConstructor_PreConfiguredSelectors() public view {
        assertTrue(
            minimalAccount.isSelectorSupported(bytes4(0xc04b8d59)),
            "exactInput"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(bytes4(0x414bf389)),
            "exactInputSingle"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(bytes4(0xf28c0498)),
            "exactOutput"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(bytes4(0xdb3e2198)),
            "exactOutputSingle"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(SUPPLY_SELECTOR),
            "supply"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(WITHDRAW_SELECTOR),
            "withdraw"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(BORROW_SELECTOR),
            "borrow"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(REPAY_SELECTOR),
            "repay"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(APPROVE_SELECTOR),
            "approve"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(PERMIT2_PERMIT_SELECTOR),
            "permit2.permit"
        );
        assertTrue(
            minimalAccount.isSelectorSupported(UNIVERSAL_EXECUTE_SELECTOR),
            "universal.execute"
        );
    }

    function testConstructor_PreConfiguredAllowedAddresses() public view {
        assertTrue(
            minimalAccount.isAllowedAddress(UNIVERSAL_ROUTER),
            "Universal Router allowed"
        );
        assertTrue(minimalAccount.isAllowedAddress(PERMIT2), "Permit2 allowed");
        assertTrue(minimalAccount.isAllowedAddress(USDT), "USDT allowed");
        assertTrue(minimalAccount.isAllowedAddress(USDC), "USDC allowed");
        assertTrue(minimalAccount.isAllowedAddress(WBTC), "WBTC allowed");
        assertTrue(minimalAccount.isAllowedAddress(WBRL), "WBRL allowed");
    }

    // ============================================================
    // CELO FORK: Swap USDT -> WBTC (Owner)
    // ============================================================

    function testCeloFork_SwapUSDTtoWBTC_Owner() public {
        IERC20 usdt = IERC20(USDT);
        IERC20 wbtc = IERC20(WBTC);

        vm.prank(USDT_HOLDER);
        usdt.transfer(address(minimalAccount), SWAP_AMOUNT_USDT);

        _setupApproves(USDT, false);

        bytes memory path = abi.encodePacked(USDT, uint24(3000), WBTC);
        uint256 usdtBefore = usdt.balanceOf(address(minimalAccount));
        uint256 wbtcBefore = wbtc.balanceOf(address(minimalAccount));

        _executeSwap(USDT, SWAP_AMOUNT_USDT, path, false);

        assertLt(
            usdt.balanceOf(address(minimalAccount)),
            usdtBefore,
            "USDT should decrease"
        );
        assertGt(
            wbtc.balanceOf(address(minimalAccount)),
            wbtcBefore,
            "WBTC should increase"
        );

        console2.log("=== USDT -> WBTC (Owner) ===");
        console2.log(
            "USDT spent:",
            usdtBefore - usdt.balanceOf(address(minimalAccount))
        );
        console2.log(
            "WBTC gained:",
            wbtc.balanceOf(address(minimalAccount)) - wbtcBefore
        );
    }

    // ============================================================
    // CELO FORK: Swap USDT -> WBTC (Adgent)
    // ============================================================

    function testCeloFork_SwapUSDTtoWBTC_Adgent() public {
        IERC20 usdt = IERC20(USDT);
        IERC20 wbtc = IERC20(WBTC);

        vm.prank(USDT_HOLDER);
        usdt.transfer(address(minimalAccount), SWAP_AMOUNT_USDT);

        _setupApproves(USDT, true);

        bytes memory path = abi.encodePacked(USDT, uint24(3000), WBTC);
        uint256 usdtBefore = usdt.balanceOf(address(minimalAccount));
        uint256 wbtcBefore = wbtc.balanceOf(address(minimalAccount));

        _executeSwap(USDT, SWAP_AMOUNT_USDT, path, true);

        assertLt(
            usdt.balanceOf(address(minimalAccount)),
            usdtBefore,
            "USDT should decrease"
        );
        assertGt(
            wbtc.balanceOf(address(minimalAccount)),
            wbtcBefore,
            "WBTC should increase"
        );

        console2.log("=== USDT -> WBTC (Adgent) ===");
        console2.log(
            "USDT spent:",
            usdtBefore - usdt.balanceOf(address(minimalAccount))
        );
        console2.log(
            "WBTC gained:",
            wbtc.balanceOf(address(minimalAccount)) - wbtcBefore
        );
    }

    // ============================================================
    // CELO FORK: Swap wBRL -> USDT (Owner)
    // ============================================================

    function testCeloFork_SwapWBRLtoUSDT_Owner() public {
        IERC20 wbrl = IERC20(WBRL);
        IERC20 usdt = IERC20(USDT);

        deal(WBRL, address(minimalAccount), SWAP_AMOUNT_WBRL);

        _setupApproves(WBRL, false);

        bytes memory path = abi.encodePacked(WBRL, uint24(100), USDT);
        uint256 wbrlBefore = wbrl.balanceOf(address(minimalAccount));
        uint256 usdtBefore = usdt.balanceOf(address(minimalAccount));

        _executeSwap(WBRL, SWAP_AMOUNT_WBRL, path, false);

        assertLt(
            wbrl.balanceOf(address(minimalAccount)),
            wbrlBefore,
            "wBRL should decrease"
        );
        assertGt(
            usdt.balanceOf(address(minimalAccount)),
            usdtBefore,
            "USDT should increase"
        );

        console2.log("=== wBRL -> USDT (Owner) ===");
        console2.log(
            "wBRL spent:",
            wbrlBefore - wbrl.balanceOf(address(minimalAccount))
        );
        console2.log(
            "USDT gained:",
            usdt.balanceOf(address(minimalAccount)) - usdtBefore
        );
    }

    // ============================================================
    // CELO FORK: Swap wBRL -> USDT (Adgent)
    // ============================================================

    function testCeloFork_SwapWBRLtoUSDT_Adgent() public {
        IERC20 wbrl = IERC20(WBRL);
        IERC20 usdt = IERC20(USDT);

        deal(WBRL, address(minimalAccount), SWAP_AMOUNT_WBRL);

        _setupApproves(WBRL, true);

        bytes memory path = abi.encodePacked(WBRL, uint24(100), USDT);
        uint256 wbrlBefore = wbrl.balanceOf(address(minimalAccount));
        uint256 usdtBefore = usdt.balanceOf(address(minimalAccount));

        _executeSwap(WBRL, SWAP_AMOUNT_WBRL, path, true);

        assertLt(
            wbrl.balanceOf(address(minimalAccount)),
            wbrlBefore,
            "wBRL should decrease"
        );
        assertGt(
            usdt.balanceOf(address(minimalAccount)),
            usdtBefore,
            "USDT should increase"
        );

        console2.log("=== wBRL -> USDT (Adgent) ===");
        console2.log(
            "wBRL spent:",
            wbrlBefore - wbrl.balanceOf(address(minimalAccount))
        );
        console2.log(
            "USDT gained:",
            usdt.balanceOf(address(minimalAccount)) - usdtBefore
        );
    }

    // ============================================================
    // CELO FORK: Swap multihop wBRL -> USDT -> WBTC (Owner)
    // ============================================================

    function testCeloFork_SwapWBRLtoUSDTtoWBTC_Owner() public {
        IERC20 wbrl = IERC20(WBRL);
        IERC20 wbtc = IERC20(WBTC);

        deal(WBRL, address(minimalAccount), SWAP_AMOUNT_WBRL);

        _setupApproves(WBRL, false);

        // Multihop: wBRL -> USDT -> WBTC
        bytes memory path = abi.encodePacked(
            WBRL,
            uint24(100), // wBRL -> USDT (fee 100)
            USDT,
            uint24(3000), // USDT -> WBTC (fee 3000)
            WBTC
        );
        uint256 wbrlBefore = wbrl.balanceOf(address(minimalAccount));
        uint256 wbtcBefore = wbtc.balanceOf(address(minimalAccount));

        _executeSwap(WBRL, SWAP_AMOUNT_WBRL, path, false);

        assertLt(
            wbrl.balanceOf(address(minimalAccount)),
            wbrlBefore,
            "wBRL should decrease"
        );
        assertGt(
            wbtc.balanceOf(address(minimalAccount)),
            wbtcBefore,
            "WBTC should increase"
        );

        console2.log("=== wBRL -> USDT -> WBTC (Owner) ===");
        console2.log(
            "wBRL spent:",
            wbrlBefore - wbrl.balanceOf(address(minimalAccount))
        );
        console2.log(
            "WBTC gained:",
            wbtc.balanceOf(address(minimalAccount)) - wbtcBefore
        );
    }

    // ============================================================
    // CELO FORK: Swap multihop wBRL -> USDT -> WBTC (Adgent)
    // ============================================================

    function testCeloFork_SwapWBRLtoUSDTtoWBTC_Adgent() public {
        IERC20 wbrl = IERC20(WBRL);
        IERC20 wbtc = IERC20(WBTC);

        deal(WBRL, address(minimalAccount), SWAP_AMOUNT_WBRL);

        _setupApproves(WBRL, true);

        bytes memory path = abi.encodePacked(
            WBRL,
            uint24(100), // wBRL -> USDT (fee 100)
            USDT,
            uint24(3000), // USDT -> WBTC (fee 3000)
            WBTC
        );
        uint256 wbrlBefore = wbrl.balanceOf(address(minimalAccount));
        uint256 wbtcBefore = wbtc.balanceOf(address(minimalAccount));

        _executeSwap(WBRL, SWAP_AMOUNT_WBRL, path, true);

        assertLt(
            wbrl.balanceOf(address(minimalAccount)),
            wbrlBefore,
            "wBRL should decrease"
        );
        assertGt(
            wbtc.balanceOf(address(minimalAccount)),
            wbtcBefore,
            "WBTC should increase"
        );

        console2.log("=== wBRL -> USDT -> WBTC (Adgent) ===");
        console2.log(
            "wBRL spent:",
            wbrlBefore - wbrl.balanceOf(address(minimalAccount))
        );
        console2.log(
            "WBTC gained:",
            wbtc.balanceOf(address(minimalAccount)) - wbtcBefore
        );
    }

    // ============================================================
    // CELO FORK: Supply USDT to Aave V3 (Owner)
    // ============================================================

    function testCeloFork_SupplyUSDTtoAave_Owner() public {
        IERC20 usdt = IERC20(USDT);

        vm.prank(USDT_HOLDER);
        usdt.transfer(address(minimalAccount), SWAP_AMOUNT_USDT);

        // Approve USDT al Aave Pool
        _executeAsOwner(USDT, 0, abi.encodeWithSelector(
            APPROVE_SELECTOR, AAVE_POOL, type(uint256).max
        ));

        // Supply USDT
        _executeAsOwner(AAVE_POOL, 0, abi.encodeWithSelector(
            SUPPLY_SELECTOR, USDT, SWAP_AMOUNT_USDT, address(minimalAccount), uint16(0)
        ));

        assertEq(
            usdt.balanceOf(address(minimalAccount)),
            0,
            "USDT should be 0 after supply"
        );

        console2.log("=== Supply USDT to Aave (Owner) ===");
        console2.log("USDT supplied:", SWAP_AMOUNT_USDT);
    }

    // ============================================================
    // CELO FORK: Supply USDT to Aave V3 (Adgent)
    // ============================================================

    function testCeloFork_SupplyUSDTtoAave_Adgent() public {
        IERC20 usdt = IERC20(USDT);

        vm.prank(USDT_HOLDER);
        usdt.transfer(address(minimalAccount), SWAP_AMOUNT_USDT);

        _executeAsAdgent(USDT, 0, abi.encodeWithSelector(
            APPROVE_SELECTOR, AAVE_POOL, type(uint256).max
        ));

        _executeAsAdgent(AAVE_POOL, 0, abi.encodeWithSelector(
            SUPPLY_SELECTOR, USDT, SWAP_AMOUNT_USDT, address(minimalAccount), uint16(0)
        ));

        assertEq(
            usdt.balanceOf(address(minimalAccount)),
            0,
            "USDT should be 0 after supply"
        );

        console2.log("=== Supply USDT to Aave (Adgent) ===");
        console2.log("USDT supplied:", SWAP_AMOUNT_USDT);
    }

    // ============================================================
    // CELO FORK: Borrow WETH from Aave V3 (Owner)
    // ============================================================

    function testCeloFork_BorrowWETHfromAave_Owner() public {
        IERC20 weth = IERC20(WETH);

        // Setup: supply USDT como colateral
        _supplyUSDTtoAave(false);

        // Borrow WETH
        uint256 wethBefore = weth.balanceOf(address(minimalAccount));
        _executeAsOwner(AAVE_POOL, 0, abi.encodeWithSelector(
            BORROW_SELECTOR,
            WETH,
            BORROW_AMOUNT_WETH,
            uint256(2), // interestRateMode = variable
            uint16(0),  // referralCode
            address(minimalAccount) // onBehalfOf
        ));

        assertGt(
            weth.balanceOf(address(minimalAccount)),
            wethBefore,
            "WETH should increase after borrow"
        );

        console2.log("=== Borrow WETH from Aave (Owner) ===");
        console2.log("WETH borrowed:", weth.balanceOf(address(minimalAccount)) - wethBefore);
    }

    // ============================================================
    // CELO FORK: Borrow WETH from Aave V3 (Adgent)
    // ============================================================

    function testCeloFork_BorrowWETHfromAave_Adgent() public {
        IERC20 weth = IERC20(WETH);

        _supplyUSDTtoAave(true);

        uint256 wethBefore = weth.balanceOf(address(minimalAccount));
        _executeAsAdgent(AAVE_POOL, 0, abi.encodeWithSelector(
            BORROW_SELECTOR,
            WETH,
            BORROW_AMOUNT_WETH,
            uint256(2),
            uint16(0),
            address(minimalAccount)
        ));

        assertGt(
            weth.balanceOf(address(minimalAccount)),
            wethBefore,
            "WETH should increase after borrow"
        );

        console2.log("=== Borrow WETH from Aave (Adgent) ===");
        console2.log("WETH borrowed:", weth.balanceOf(address(minimalAccount)) - wethBefore);
    }

    // ============================================================
    // CELO FORK: Repay WETH to Aave V3 (Owner)
    // ============================================================

    function testCeloFork_RepayWETHtoAave_Owner() public {
        IERC20 weth = IERC20(WETH);

        // Setup: supply colateral + borrow
        _supplyUSDTtoAave(false);
        _executeAsOwner(AAVE_POOL, 0, abi.encodeWithSelector(
            BORROW_SELECTOR, WETH, BORROW_AMOUNT_WETH, uint256(2), uint16(0), address(minimalAccount)
        ));

        // Approve WETH al Aave Pool (necesario para repay)
        _executeAsOwner(WETH, 0, abi.encodeWithSelector(
            APPROVE_SELECTOR, AAVE_POOL, type(uint256).max
        ));

        // Repay
        uint256 wethBefore = weth.balanceOf(address(minimalAccount));
        _executeAsOwner(AAVE_POOL, 0, abi.encodeWithSelector(
            REPAY_SELECTOR,
            WETH,
            REPAY_AMOUNT_WETH,
            uint256(2), // interestRateMode = variable
            address(minimalAccount) // onBehalfOf
        ));

        assertLt(
            weth.balanceOf(address(minimalAccount)),
            wethBefore,
            "WETH should decrease after repay"
        );

        console2.log("=== Repay WETH to Aave (Owner) ===");
        console2.log("WETH repaid:", wethBefore - weth.balanceOf(address(minimalAccount)));
    }

    // ============================================================
    // CELO FORK: Repay WETH to Aave V3 (Adgent)
    // ============================================================

    function testCeloFork_RepayWETHtoAave_Adgent() public {
        IERC20 weth = IERC20(WETH);

        _supplyUSDTtoAave(true);
        _executeAsAdgent(AAVE_POOL, 0, abi.encodeWithSelector(
            BORROW_SELECTOR, WETH, BORROW_AMOUNT_WETH, uint256(2), uint16(0), address(minimalAccount)
        ));

        _executeAsAdgent(WETH, 0, abi.encodeWithSelector(
            APPROVE_SELECTOR, AAVE_POOL, type(uint256).max
        ));

        uint256 wethBefore = weth.balanceOf(address(minimalAccount));
        _executeAsAdgent(AAVE_POOL, 0, abi.encodeWithSelector(
            REPAY_SELECTOR,
            WETH,
            REPAY_AMOUNT_WETH,
            uint256(2),
            address(minimalAccount)
        ));

        assertLt(
            weth.balanceOf(address(minimalAccount)),
            wethBefore,
            "WETH should decrease after repay"
        );

        console2.log("=== Repay WETH to Aave (Adgent) ===");
        console2.log("WETH repaid:", wethBefore - weth.balanceOf(address(minimalAccount)));
    }

    // ============================================================
    // CELO FORK: Withdraw USDT from Aave V3 (Owner)
    // ============================================================

    function testCeloFork_WithdrawUSDTfromAave_Owner() public {
        IERC20 usdt = IERC20(USDT);

        // Setup: supply USDT primero
        _supplyUSDTtoAave(false);

        // Withdraw USDT
        uint256 usdtBefore = usdt.balanceOf(address(minimalAccount));
        _executeAsOwner(AAVE_POOL, 0, abi.encodeWithSelector(
            WITHDRAW_SELECTOR,
            USDT,
            WITHDRAW_AMOUNT_USDT,
            address(minimalAccount) // to
        ));

        assertGt(
            usdt.balanceOf(address(minimalAccount)),
            usdtBefore,
            "USDT should increase after withdraw"
        );

        console2.log("=== Withdraw USDT from Aave (Owner) ===");
        console2.log("USDT withdrawn:", usdt.balanceOf(address(minimalAccount)) - usdtBefore);
    }

    // ============================================================
    // CELO FORK: Withdraw USDT from Aave V3 (Adgent)
    // ============================================================

    function testCeloFork_WithdrawUSDTfromAave_Adgent() public {
        IERC20 usdt = IERC20(USDT);

        _supplyUSDTtoAave(true);

        uint256 usdtBefore = usdt.balanceOf(address(minimalAccount));
        _executeAsAdgent(AAVE_POOL, 0, abi.encodeWithSelector(
            WITHDRAW_SELECTOR,
            USDT,
            WITHDRAW_AMOUNT_USDT,
            address(minimalAccount)
        ));

        assertGt(
            usdt.balanceOf(address(minimalAccount)),
            usdtBefore,
            "USDT should increase after withdraw"
        );

        console2.log("=== Withdraw USDT from Aave (Adgent) ===");
        console2.log("USDT withdrawn:", usdt.balanceOf(address(minimalAccount)) - usdtBefore);
    }
}