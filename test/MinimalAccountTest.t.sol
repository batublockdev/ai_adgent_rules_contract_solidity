// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {MinimalAccount} from "src/ethereum/MinimalAccount.sol";
import {ERC20Mock} from "./mock/ERC20Mock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    MessageHashUtils
} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MinimalAccountTest is Test {
    using MessageHashUtils for bytes32;

    MinimalAccount minimalAccount;
    ERC20Mock usdc;

    // Anvil default accounts
    address constant OWNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address constant ADGENT = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    uint256 constant OWNER_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant ADGENT_KEY =
        0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    address randomUser = makeAddr("randomUser");
    uint256 constant AMOUNT = 1e18;

    function setUp() public {
        // Deploy con owner = msg.sender (OWNER) y adgent = ADGENT
        vm.prank(OWNER);
        minimalAccount = new MinimalAccount(ADGENT);

        // Deploy mock USDC
        usdc = new ERC20Mock("USD Coin", "USDC", 0, address(minimalAccount));

        // Registrar USDC como target y selectors que vamos a usar en tests
        vm.startPrank(OWNER);
        minimalAccount.registerTarget(address(usdc));
        minimalAccount.registerSelector(ERC20Mock.mint.selector, 0);
        minimalAccount.registerSelector(IERC20.transfer.selector, 0);
        minimalAccount.registerSelector(IERC20.approve.selector, 0);
        vm.stopPrank();
    }

    // ============================================================
    // HELPERS
    // ============================================================

    /// @dev Firma (target, value, keccak256(data), nonce, chainId) con la key dada
    function _signExecution(
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 chainId,
        uint256 privateKey
    ) internal pure returns (bytes memory) {
        bytes32 hash = keccak256(
            abi.encode(target, value, keccak256(data), nonce, chainId)
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Firma un batch completo
    function _signBatch(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory datas,
        uint256 nonce,
        uint256 chainId,
        uint256 privateKey
    ) internal pure returns (bytes memory) {
        uint256 len = targets.length;
        bytes32[] memory dataHashes = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            dataHashes[i] = keccak256(datas[i]);
        }
        bytes32 batchHash = keccak256(
            abi.encode(targets, values, dataHashes, nonce, chainId)
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(
            batchHash
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    // ============================================================
    // EXECUTE — SIGNATURE VALIDATION
    // ============================================================

    function testExecute_OwnerSignature_Valid() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        // Cualquiera puede enviar, lo que importa es la signature
        vm.prank(randomUser);
        minimalAccount.execute(address(usdc), 0, data, sig);

        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testExecute_AdgentSignature_Valid() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            ADGENT_KEY
        );

        vm.prank(randomUser);
        minimalAccount.execute(address(usdc), 0, data, sig);

        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testExecute_InvalidSignature_Reverts() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        // Firmar con una key que no es owner ni adgent
        uint256 wrongKey = 0xDEADBEEF;
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            wrongKey
        );

        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__InvalidSignature.selector
        );
        minimalAccount.execute(address(usdc), 0, data, sig);
    }

    function testExecute_SignatureLengthNot65_Reverts() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory badSig = new bytes(64); // no 65

        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__InvalidSignatureLength.selector
        );
        minimalAccount.execute(address(usdc), 0, data, badSig);
    }

    // ============================================================
    // EXECUTE — NONCE / REPLAY PROTECTION
    // ============================================================

    function testExecute_NonceIncrements() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        assertEq(minimalAccount.nonce(), 0);

        bytes memory sig1 = _signExecution(
            address(usdc),
            0,
            data,
            0,
            block.chainid,
            OWNER_KEY
        );
        vm.prank(randomUser);
        minimalAccount.execute(address(usdc), 0, data, sig1);
        assertEq(minimalAccount.nonce(), 1);

        // Segunda tx con nonce=1
        bytes memory sig2 = _signExecution(
            address(usdc),
            0,
            data,
            1,
            block.chainid,
            OWNER_KEY
        );
        vm.prank(randomUser);
        minimalAccount.execute(address(usdc), 0, data, sig2);
        assertEq(minimalAccount.nonce(), 2);
    }

    function testExecute_ReplayWithOldNonce_Reverts() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        // nonce 0
        bytes memory sig0 = _signExecution(
            address(usdc),
            0,
            data,
            0,
            block.chainid,
            OWNER_KEY
        );
        vm.prank(randomUser);
        minimalAccount.execute(address(usdc), 0, data, sig0);

        // Reintentar con nonce 0 otra vez → signature inválida porque el hash incluye nonce actual (1)
        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__InvalidSignature.selector
        );
        minimalAccount.execute(address(usdc), 0, data, sig0);
    }

    function testExecute_WrongChainId_Reverts() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        // Firmar con chainId equivocado
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            99999,
            OWNER_KEY
        );

        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__InvalidSignature.selector
        );
        minimalAccount.execute(address(usdc), 0, data, sig);
    }

    // ============================================================
    // EXECUTE — WHITELIST VALIDATION
    // ============================================================

    function testExecute_TargetNotRegistered_Reverts() public {
        address unregistered = address(0xDEAD);
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            unregistered,
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                MinimalAccount.TargetNotRegistered.selector,
                unregistered
            )
        );
        minimalAccount.execute(unregistered, 0, data, sig);
    }

    function testExecute_SelectorNotRegistered_Reverts() public {
        bytes4 badSelector = bytes4(0xDEADBEEF);
        bytes memory data = abi.encodeWithSelector(
            badSelector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                MinimalAccount.SelectorNotRegistered.selector,
                badSelector
            )
        );
        minimalAccount.execute(address(usdc), 0, data, sig);
    }

    function testExecute_RemovedTarget_Reverts() public {
        address tempTarget = address(0xBEEF);
        vm.startPrank(OWNER);
        minimalAccount.registerTarget(tempTarget);
        minimalAccount.registerSelector(ERC20Mock.mint.selector, 0);
        minimalAccount.removeTarget(tempTarget);
        vm.stopPrank();

        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            tempTarget,
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                MinimalAccount.TargetNotRegistered.selector,
                tempTarget
            )
        );
        minimalAccount.execute(tempTarget, 0, data, sig);
    }

    function testExecute_RemovedSelector_Reverts() public {
        bytes4 sel = bytes4(0xCAFEBABE);
        vm.startPrank(OWNER);
        minimalAccount.registerSelector(sel, 32);
        minimalAccount.removeSelector(sel);
        vm.stopPrank();

        bytes memory data = abi.encodeWithSelector(
            sel,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                MinimalAccount.SelectorNotRegistered.selector,
                sel
            )
        );
        minimalAccount.execute(address(usdc), 0, data, sig);
    }

    // ============================================================
    // EXECUTE — RECIPIENT VALIDATION
    // ============================================================

    function testExecute_RecipientIsSelf_Valid() public {
        // mint a address(this) → recipient = address(minimalAccount) = address(this)
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        minimalAccount.execute(address(usdc), 0, data, sig);

        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testExecute_RecipientNotSelf_NotAllowed_Reverts() public {
        // Registrar un selector con offset 0 para que lea el primer param como recipient
        // ERC20Mock.mint(address to, uint256 amount) → offset 0 = `to`
        // Pero mint ya está registrado con offset 0, y to = randomUser (no address(this))
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            randomUser, // recipient != address(this)
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                MinimalAccount.RecipientInvalido.selector,
                0,
                ERC20Mock.mint.selector,
                randomUser,
                address(minimalAccount)
            )
        );
        minimalAccount.execute(address(usdc), 0, data, sig);
    }

    function testExecute_RecipientNotAllowedButInWhitelist_Valid() public {
        // Agregar randomUser como allowed address
        vm.prank(OWNER);
        minimalAccount.setAllowedAddress(randomUser);

        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            randomUser, // recipient en whitelist
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        minimalAccount.execute(address(usdc), 0, data, sig);

        assertEq(usdc.balanceOf(randomUser), AMOUNT);
    }

    // ============================================================
    // EXECUTE — CALL FAILURE
    // ============================================================

    function testExecute_CallFailed_Reverts() public {
        // transfer con balance insuficiente
        bytes memory data = abi.encodeWithSelector(
            IERC20.transfer.selector,
            randomUser,
            type(uint256).max // más de lo que tiene
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.execute(address(usdc), 0, data, sig);
    }

    // ============================================================
    // BATCH EXECUTE
    // ============================================================

    function testBatchExecute_TwoOps_BothExecute() public {
        // Op 1: mint 1e18 a minimalAccount
        // Op 2: mint 2e18 a minimalAccount
        address[] memory targets = new address[](2);
        targets[0] = address(usdc);
        targets[1] = address(usdc);

        uint256[] memory values = new uint256[](2);
        values[0] = 0;
        values[1] = 0;

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            1e18
        );
        datas[1] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            2e18
        );

        bytes memory sig = _signBatch(
            targets,
            values,
            datas,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        minimalAccount.batchExecute(targets, values, datas, sig);

        assertEq(usdc.balanceOf(address(minimalAccount)), 3e18);
        assertEq(minimalAccount.nonce(), 2);
    }

    function testBatchExecute_AdgentSignature_Valid() public {
        address[] memory targets = new address[](1);
        targets[0] = address(usdc);

        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        bytes memory sig = _signBatch(
            targets,
            values,
            datas,
            minimalAccount.nonce(),
            block.chainid,
            ADGENT_KEY
        );

        vm.prank(randomUser);
        minimalAccount.batchExecute(targets, values, datas, sig);

        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testBatchExecute_InvalidSignature_Reverts() public {
        address[] memory targets = new address[](1);
        targets[0] = address(usdc);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        bytes memory sig = _signBatch(
            targets,
            values,
            datas,
            minimalAccount.nonce(),
            block.chainid,
            0xDEADBEEF
        );

        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__InvalidSignature.selector
        );
        minimalAccount.batchExecute(targets, values, datas, sig);
    }

    function testBatchExecute_LengthMismatch_Reverts() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](1); // mismatch
        bytes[] memory datas = new bytes[](2);

        bytes memory sig = new bytes(65);

        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__BatchLengthMismatch.selector
        );
        minimalAccount.batchExecute(targets, values, datas, sig);
    }

    function testBatchExecute_OneOpFails_AllReverts() public {
        // Op 1: mint (válido)
        // Op 2: transfer con balance insuficiente (falla) → todo revierte
        address[] memory targets = new address[](2);
        targets[0] = address(usdc);
        targets[1] = address(usdc);

        uint256[] memory values = new uint256[](2);

        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            1e18
        );
        datas[1] = abi.encodeWithSelector(
            IERC20.transfer.selector,
            randomUser,
            type(uint256).max // falla: no tiene tanto
        );

        bytes memory sig = _signBatch(
            targets,
            values,
            datas,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        uint256 balanceBefore = usdc.balanceOf(address(minimalAccount));

        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.batchExecute(targets, values, datas, sig);

        // Nada cambió (all-or-nothing)
        assertEq(usdc.balanceOf(address(minimalAccount)), balanceBefore);
        // Nonce no incrementó porque todo revirtió
        assertEq(minimalAccount.nonce(), 0);
    }

    function testBatchExecute_NonceIncrementsPerOp() public {
        address[] memory targets = new address[](3);
        targets[0] = address(usdc);
        targets[1] = address(usdc);
        targets[2] = address(usdc);

        uint256[] memory values = new uint256[](3);

        bytes[] memory datas = new bytes[](3);
        datas[0] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            1e18
        );
        datas[1] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            2e18
        );
        datas[2] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            3e18
        );

        bytes memory sig = _signBatch(
            targets,
            values,
            datas,
            0,
            block.chainid,
            OWNER_KEY
        );

        vm.prank(randomUser);
        minimalAccount.batchExecute(targets, values, datas, sig);

        assertEq(minimalAccount.nonce(), 3);
        assertEq(usdc.balanceOf(address(minimalAccount)), 6e18);
    }

    function testBatchExecute_SignatureLengthNot65_Reverts() public {
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        bytes memory badSig = new bytes(64);

        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__InvalidSignatureLength.selector
        );
        minimalAccount.batchExecute(targets, values, datas, badSig);
    }

    // ============================================================
    // PAUSE
    // ============================================================

    function testPause_BlocksExecute() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(OWNER);
        minimalAccount.pause();

        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__OperationsInPauseMode.selector
        );
        minimalAccount.execute(address(usdc), 0, data, sig);
    }

    function testPause_BlocksBatchExecute() public {
        address[] memory targets = new address[](1);
        targets[0] = address(usdc);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        bytes memory sig = _signBatch(
            targets,
            values,
            datas,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.prank(OWNER);
        minimalAccount.pause();

        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__OperationsInPauseMode.selector
        );
        minimalAccount.batchExecute(targets, values, datas, sig);
    }

    function testUnpause_AllowsExecute() public {
        bytes memory data = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory sig = _signExecution(
            address(usdc),
            0,
            data,
            minimalAccount.nonce(),
            block.chainid,
            OWNER_KEY
        );

        vm.startPrank(OWNER);
        minimalAccount.pause();
        minimalAccount.pause(); // despausa
        vm.stopPrank();

        vm.prank(randomUser);
        minimalAccount.execute(address(usdc), 0, data, sig);

        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testPause_OnlyOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.pause();
    }

    function testGetPause_ReturnsState() public {
        assertFalse(minimalAccount.getPause());

        vm.prank(OWNER);
        minimalAccount.pause();

        assertTrue(minimalAccount.getPause());
    }

    // ============================================================
    // ACCESS CONTROL — ADMIN FUNCTIONS
    // ============================================================

    function testRegisterTarget_OnlyOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.registerTarget(address(0x123));
    }

    function testRemoveTarget_OnlyOwner() public {
        vm.prank(OWNER);
        minimalAccount.registerTarget(address(0x123));

        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.removeTarget(address(0x123));
    }

    function testRegisterSelector_OnlyOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.registerSelector(bytes4(0x12345678), 32);
    }

    function testRemoveSelector_OnlyOwner() public {
        vm.prank(OWNER);
        minimalAccount.registerSelector(bytes4(0x12345678), 32);

        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.removeSelector(bytes4(0x12345678));
    }

    function testSetAdgent_OnlyOwner() public {
        address newAdgent = makeAddr("newAdgent");
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.setAdgent(newAdgent);
    }

    function testSetAdgent_ChangesAdgent() public {
        address newAdgent = makeAddr("newAdgent");

        vm.prank(OWNER);
        minimalAccount.setAdgent(newAdgent);

        assertEq(minimalAccount.getAdgent(), newAdgent);
    }

    function testSetAllowedAddress_OnlyOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.setAllowedAddress(randomUser);
    }

    function testRemoveAllowedAddress_OnlyOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.removeAllowedAddress(randomUser);
    }

    // ============================================================
    // WITHDRAW TOKEN
    // ============================================================

    function testWithdrawToken_OnlyOwner() public {
        usdc.mint(address(minimalAccount), AMOUNT);
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.withdrawToken(address(usdc), AMOUNT);
    }

    function testWithdrawToken_TransfersToOwner() public {
        // El contrato tiene USDC del setUp (1000e18)
        usdc.mint(address(minimalAccount), AMOUNT);

        uint256 ownerBefore = usdc.balanceOf(OWNER);
        uint256 contractBefore = usdc.balanceOf(address(minimalAccount));

        vm.prank(OWNER);
        minimalAccount.withdrawToken(address(usdc), AMOUNT);

        assertEq(usdc.balanceOf(OWNER), ownerBefore + AMOUNT);
        assertEq(
            usdc.balanceOf(address(minimalAccount)),
            contractBefore - AMOUNT
        );
    }

    function testWithdrawToken_EmitsEvent() public {
        usdc.mint(address(minimalAccount), AMOUNT);

        vm.prank(OWNER);
        vm.expectEmit(true, false, false, true);
        emit MinimalAccount.TokenWithdrawn(address(usdc), AMOUNT);
        minimalAccount.withdrawToken(address(usdc), AMOUNT);
    }

    // ============================================================
    // WITHDRAW CELO
    // ============================================================

    function testWithdrawCelo_OnlyOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.withdrawCelo(1 ether);
    }

    function testWithdrawCelo_TransfersToOwner() public {
        vm.deal(address(minimalAccount), 5 ether);
        uint256 ownerBefore = OWNER.balance;

        vm.prank(OWNER);
        minimalAccount.withdrawCelo(3 ether);

        assertEq(OWNER.balance, ownerBefore + 3 ether);
        assertEq(address(minimalAccount).balance, 2 ether);
    }

    function testWithdrawCelo_EmitsEvent() public {
        vm.deal(address(minimalAccount), 1 ether);

        vm.prank(OWNER);
        vm.expectEmit(false, false, false, true);
        emit MinimalAccount.CeloWithdrawn(1 ether);
        minimalAccount.withdrawCelo(1 ether);
    }

    // ============================================================
    // RECEIVE ETHER
    // ============================================================

    function testReceiveEther() public {
        uint256 balanceBefore = address(minimalAccount).balance;
        (bool success, ) = address(minimalAccount).call{value: 1 ether}("");
        assertTrue(success);
        assertEq(address(minimalAccount).balance, balanceBefore + 1 ether);
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    function testGetAdgent_ReturnsInitialAdgent() public {
        assertEq(minimalAccount.getAdgent(), ADGENT);
    }

    function testIsAllowedTarget_DefaultFalse() public {
        assertFalse(minimalAccount.isAllowedTarget(address(0x123)));
    }

    function testIsAllowedTarget_TrueAfterRegister() public {
        vm.prank(OWNER);
        minimalAccount.registerTarget(address(0x123));
        assertTrue(minimalAccount.isAllowedTarget(address(0x123)));
    }

    function testIsAllowedTarget_FalseAfterRemove() public {
        vm.startPrank(OWNER);
        minimalAccount.registerTarget(address(0x123));
        minimalAccount.removeTarget(address(0x123));
        vm.stopPrank();
        assertFalse(minimalAccount.isAllowedTarget(address(0x123)));
    }

    function testIsSelectorSupported_PreRegisteredSelectors() public {
        // Selectores pre-registrados en el constructor
        assertTrue(minimalAccount.isSelectorSupported(bytes4(0xc04b8d59))); // exactInput
        assertTrue(minimalAccount.isSelectorSupported(bytes4(0x414bf389))); // exactInputSingle
        assertTrue(minimalAccount.isSelectorSupported(bytes4(0xf28c0498))); // exactOutput
        assertTrue(minimalAccount.isSelectorSupported(bytes4(0xdb3e2198))); // exactOutputSingle
        assertTrue(minimalAccount.isSelectorSupported(bytes4(0x617ba037))); // supply
        assertTrue(minimalAccount.isSelectorSupported(bytes4(0x69328dec))); // withdraw
        assertTrue(minimalAccount.isSelectorSupported(bytes4(0xa415bcad))); // borrow
        assertTrue(minimalAccount.isSelectorSupported(bytes4(0x573ade81))); // repay
    }

    function testIsSelectorSupported_UnregisteredFalse() public {
        assertFalse(minimalAccount.isSelectorSupported(bytes4(0xDEADBEEF)));
    }

    function testIsSelectorSupported_FalseAfterRemove() public {
        bytes4 sel = bytes4(0xCAFEBABE);
        vm.startPrank(OWNER);
        minimalAccount.registerSelector(sel, 32);
        assertTrue(minimalAccount.isSelectorSupported(sel));
        minimalAccount.removeSelector(sel);
        vm.stopPrank();
        assertFalse(minimalAccount.isSelectorSupported(sel));
    }
}
