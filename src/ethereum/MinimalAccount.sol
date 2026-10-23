// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MinimalAccount
 * @author BatuBlockDev
 * @notice Smart contract wallet with meta-transaction support.
 * The owner or an authorized AI agent (adgent) signs operations off-chain.
 * Anyone can submit the transaction by providing the signature + data.
 * The contract verifies the signature first, then runs security checks
 * (target whitelist, selector whitelist, recipient validation, pause)
 * before executing the call.
 * Designed for DeFi protocols like Uniswap V3 and Aave V3 on Celo mainnet.
 * Pre-configured with all necessary targets, selectors, and allowed addresses
 * for production use on Celo.
 */

// ////////////////////////////////////////
// ///////////// IMPORTS /////////////////
// ////////////////////////////////////////

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {
    MessageHashUtils
} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MinimalAccount is Ownable {
    // ////////////////////////////////////////
    // /////////////// ERRORS /////////////////
    // ////////////////////////////////////////

    error MinimalAccount__InvalidSignature();
    error MinimalAccount__InvalidSignatureLength();
    error MinimalAccount__OperationsInPauseMode();
    error MinimalAccount__CallFailed(bytes result);
    error MinimalAccount__BatchLengthMismatch();
    error RecipientInvalido(
        uint256 offset,
        bytes4 selector,
        address recipient,
        address expected
    );
    error SelectorNotRegistered(bytes4 selector);
    error TargetNotRegistered(address target);

    // ////////////////////////////////////////
    // //////////// TYPE DECLARATIONS //////////
    // ////////////////////////////////////////

    // (No custom types needed)

    // ////////////////////////////////////////
    // //////////// STATE VARIABLES ////////////
    // ////////////////////////////////////////

    /// @notice The authorized AI agent address that can sign operations
    address private _adgent;
    /// @notice Pause state — when true, all operations are blocked
    bool private _pause;
    /// @notice Simple incremental nonce to prevent replay attacks
    uint256 public nonce;

    /// @notice Whitelist of allowed target contracts that can be called
    mapping(address => bool) public isAllowedTarget;
    /// @notice Offset of the recipient address within the calldata for each selector
    mapping(bytes4 => uint256) public functionAddressOffsets;
    /// @notice Whitelist of allowed function selectors that can be executed
    mapping(bytes4 => bool) public isSelectorSupported;
    /// @notice Whitelist of addresses allowed to be recipient/spender (approve, permit, etc.)
    mapping(address => bool) public isAllowedAddress;

    // ////////////////////////////////////////
    // /////// CELO MAINNET CONSTANTS /////////
    // ////////////////////////////////////////

    // --- Uniswap V3: Universal Router ---
    address constant UNIVERSAL_ROUTER = 0xe2023F3FA515cF070e07fD9d51c1d236e07843f4;

    // --- Permit2 ---
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    // --- Aave V3 Pool ---
    address constant AAVE_POOL = 0x3E59A31363E2ad014dcbc521c4a0d5757d9f3402;

    // --- Tokens soportados en Celo mainnet ---
    address constant USDT = 0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e;
    address constant USDC = 0xcebA9300f2b948710d2653dD7B07f33A8B32118C;
    address constant WBTC = 0x8aC2901Dd8A1F17a1A4768A6bA4C3751e3995B2D;
    address constant WETH = 0xD221812de1BD094f35587EE8E174B07B6167D9Af;
    address constant CELO = 0x471EcE3750Da237f93B8E339c536989b8978a438;
    address constant WBRL = 0xD76f5Faf6888e24D9F04Bf92a0c8B921FE4390e0;
    address constant WARS = 0x0DC4F92879B7670e5f4e4e6e3c801D229129D90D;
    address constant EURM = 0xD8763CBa276a3738E6DE85b4b3bF5FDed6D6cA73;
    address constant CHFM = 0xb55a79F398E759E43C95b979163f30eC87Ee131D;
    address constant GBPM = 0xCCF663b1fF11028f0b19058d0f7B674004a40746;
    address constant TETHER_GOLD = 0xaf37E8B6C9ED7f6318979f56Fc287d76c30847ff;
    address constant SUSHI = 0xD15EC721C2A896512Ad29C671997DD68f9593226;
    address constant ETHIX = 0x9995cc8F20Db5896943Afc8eE0ba463259c931ed;
    address constant PLASTIK = 0x27cd006548dF7C8c8e9fdc4A67fa05C2E3CA5CF9;

    // --- Selectores hardcodeados ---
    bytes4 constant APPROVE_SELECTOR = 0x095ea7b3;       // approve(address,uint256)
    bytes4 constant PERMIT2_PERMIT_SELECTOR = 0x87517c45; // permit(address,address,uint160,uint48)
    bytes4 constant UNIVERSAL_EXECUTE_SELECTOR = 0x3593564c; // execute(bytes,bytes[],uint256)

    // --- Selectores Aave V3 Pool ---
    bytes4 constant SUPPLY_SELECTOR = 0x617ba037;   // supply(address,uint256,address,uint16)
    bytes4 constant WITHDRAW_SELECTOR = 0x69328dec; // withdraw(address,uint256,address)
    bytes4 constant BORROW_SELECTOR = 0xa415bcad;   // borrow(address,uint256,uint256,uint16,address)
    bytes4 constant REPAY_SELECTOR = 0x573ade81;    // repay(address,uint256,uint256,address)

    // ////////////////////////////////////////
    // /////////////// EVENTS /////////////////
    // ////////////////////////////////////////

    /// @notice Emitted when a target contract is added to the whitelist
    event TargetRegistered(address indexed target);
    /// @notice Emitted when a target contract is removed from the whitelist
    event TargetRemoved(address indexed target);
    /// @notice Emitted when a function selector is registered with its recipient offset
    event SelectorRegistered(bytes4 indexed selector, uint256 offset);
    /// @notice Emitted when a function selector is removed from the whitelist
    event SelectorRemoved(bytes4 indexed selector);
    /// @notice Emitted when the adgent address is updated
    event AdgentUpdated(address indexed oldAdgent, address indexed newAdgent);
    /// @notice Emitted when the pause state is toggled
    event PausedToggled(bool paused);
    /// @notice Emitted when a meta-transaction is executed
    event Executed(address indexed target, uint256 value, bytes4 indexed selector, address indexed signer, uint256 nonce);
    /// @notice Emitted when a batch of meta-transactions is executed
    event BatchExecuted(uint256 count, address indexed signer, uint256 startNonce);
    /// @notice Emitted when tokens are withdrawn from the contract
    event TokenWithdrawn(address indexed token, uint256 amount);
    /// @notice Emitted when CELO is withdrawn from the contract
    event CeloWithdrawn(uint256 amount);

    // ////////////////////////////////////////
    // /////////////// MODIFIERS //////////////
    // ////////////////////////////////////////

    /// @notice Reverts if the contract is paused
    modifier PauseCheck() {
        if (_pause == true) {
            revert MinimalAccount__OperationsInPauseMode();
        }
        _;
    }

    // ////////////////////////////////////////
    // /////////////// FUNCTIONS //////////////
    // ////////////////////////////////////////

    // ////////////////////////////////////////
    // ///////////// CONSTRUCTOR //////////////
    // ////////////////////////////////////////

    /**
     * @param adgent The authorized AI agent address that can sign operations
     * @notice Initializes the account with the owner (msg.sender) and adgent.
     * Pre-configures all targets, selectors, and allowed addresses for
     * Uniswap V3, Permit2, and supported tokens on Celo mainnet.
     */
    constructor(address adgent) Ownable(msg.sender) {
        // ===== 1. SELECTORS — Uniswap V3 SwapRouter =====
        // Offsets con base 36 (32 len + 4 selector)
        _registerSelector(bytes4(0xc04b8d59), 64);  // exactInput: recipient
        _registerSelector(bytes4(0x414bf389), 96);  // exactInputSingle: recipient
        _registerSelector(bytes4(0xf28c0498), 64);  // exactOutput: recipient
        _registerSelector(bytes4(0xdb3e2198), 96);  // exactOutputSingle: recipient

        // ===== 2. SELECTORS — Aave V3 Pool =====
        _registerSelector(SUPPLY_SELECTOR, 64);   // supply: onBehalfOf
        _registerSelector(WITHDRAW_SELECTOR, 64); // withdraw: to
        _registerSelector(BORROW_SELECTOR, 128);  // borrow: onBehalfOf
        _registerSelector(REPAY_SELECTOR, 96);    // repay: onBehalfOf

        // ===== 3. SELECTORS — ERC20 / Permit2 / Universal Router =====
        _registerSelector(APPROVE_SELECTOR, 0);              // approve: spender = param 0
        _registerSelector(PERMIT2_PERMIT_SELECTOR, 0);       // permit: token = param 0
        _registerSelector(UNIVERSAL_EXECUTE_SELECTOR, 256);  // execute: recipient en offset 256

        // ===== 4. TARGETS — Contracts que se pueden llamar via execute =====
        _registerTarget(UNIVERSAL_ROUTER);
        _registerTarget(PERMIT2);
        _registerTarget(AAVE_POOL);

        // Tokens como targets (para approve, transfer, etc.)
        _registerTarget(USDT);
        _registerTarget(USDC);
        _registerTarget(WBTC);
        _registerTarget(WETH);
        _registerTarget(CELO);
        _registerTarget(WBRL);
        _registerTarget(WARS);
        _registerTarget(EURM);
        _registerTarget(CHFM);
        _registerTarget(GBPM);
        _registerTarget(TETHER_GOLD);
        _registerTarget(SUSHI);
        _registerTarget(ETHIX);
        _registerTarget(PLASTIK);

        // ===== 5. ALLOWED ADDRESSES — Recipients/spenders autorizados =====
        // approve(address spender, ...) → offset 0 lee spender → debe estar autorizado
        _setAllowedAddress(UNIVERSAL_ROUTER);
        _setAllowedAddress(PERMIT2);
        _setAllowedAddress(AAVE_POOL);

        // permit(address token, ...) → offset 0 lee token → debe estar autorizado
        _setAllowedAddress(USDT);
        _setAllowedAddress(USDC);
        _setAllowedAddress(WBTC);
        _setAllowedAddress(WETH);
        _setAllowedAddress(CELO);
        _setAllowedAddress(WBRL);
        _setAllowedAddress(WARS);
        _setAllowedAddress(EURM);
        _setAllowedAddress(CHFM);
        _setAllowedAddress(GBPM);
        _setAllowedAddress(TETHER_GOLD);
        _setAllowedAddress(SUSHI);
        _setAllowedAddress(ETHIX);
        _setAllowedAddress(PLASTIK);

        // ===== 6. STATE =====
        _adgent = adgent;
        _pause = false;
        nonce = 0;
    }

    // ////////////////////////////////////////
    // /////////////// RECEIVE ////////////////
    // ////////////////////////////////////////

    /// @notice Allows the contract to receive ETH
    receive() external payable {}

    // ////////////////////////////////////////
    // ////////// EXTERNAL FUNCTIONS //////////
    // ////////////////////////////////////////

    /**
     * @param token The ERC-20 token address to withdraw
     * @param amount The amount of tokens to withdraw
     * @notice Withdraws all tokens of the given type from the contract to the owner.
     * @dev Only callable by the owner.
     */
    function withdrawToken(address token, uint256 amount) external onlyOwner {
        bool success = IERC20(token).transfer(owner(), amount);
        if (!success) {
            revert MinimalAccount__CallFailed(bytes("Token transfer failed"));
        }
        emit TokenWithdrawn(token, amount);
    }

    /**
     * @param amount The amount of CELO (native) to withdraw
     * @notice Withdraws CELO from the contract to the owner.
     * @dev Only callable by the owner.
     */
    function withdrawCelo(uint256 amount) external onlyOwner {
        (bool success, ) = payable(owner()).call{value: amount}("");
        if (!success) {
            revert MinimalAccount__CallFailed(bytes("CELO transfer failed"));
        }
        emit CeloWithdrawn(amount);
    }

    /**
     * @notice Toggles the pause state of the contract.
     * When paused, execute is blocked.
     * @dev Only callable by the owner. Emits PausedToggled event.
     */
    function pause() external onlyOwner {
        if (_pause == true) {
            _pause = false;
        } else {
            _pause = true;
        }
        emit PausedToggled(_pause);
    }

    /**
     * @param newAdgent The new AI agent address authorized to sign operations
     * @notice Updates the adgent address. The adgent can sign operations
     * alongside the owner. Emits AdgentUpdated event.
     * @dev Only callable by the owner.
     */
    function setAdgent(address newAdgent) external onlyOwner {
        address oldAdgent = _adgent;
        _adgent = newAdgent;
        emit AdgentUpdated(oldAdgent, newAdgent);
    }

    /**
     * @param recipient The address to authorize as allowed recipient/spender
     * @notice Adds an address to the allowed recipient whitelist.
     * Used for functions like approve and permit where the extracted address
     * is not address(this) but an authorized spender contract.
     * @dev Only callable by the owner.
     */
    function setAllowedAddress(address recipient) external onlyOwner {
        _setAllowedAddress(recipient);
    }

    /**
     * @param recipient The address to remove from the allowed recipient whitelist
     * @notice Removes an address from the allowed recipient whitelist.
     * @dev Only callable by the owner.
     */
    function removeAllowedAddress(address recipient) external onlyOwner {
        isAllowedAddress[recipient] = false;
    }

    /**
     * @param target The contract address to add to the target whitelist
     * @notice Registers a target contract that can be called via execute.
     * Emits TargetRegistered event.
     * @dev Only callable by the owner.
     */
    function registerTarget(address target) external onlyOwner {
        _registerTarget(target);
    }

    /**
     * @param target The contract address to remove from the target whitelist
     * @notice Removes a target contract from the whitelist.
     * Emits TargetRemoved event.
     * @dev Only callable by the owner.
     */
    function removeTarget(address target) external onlyOwner {
        delete isAllowedTarget[target];
        emit TargetRemoved(target);
    }

    /**
     * @param selector The function selector (first 4 bytes) to register
     * @param offset The byte offset of the recipient address within the calldata
     * @notice Registers a function selector with its recipient offset.
     * The offset is relative to base 36 (32 bytes length prefix + 4 bytes selector).
     * Emits SelectorRegistered event.
     * @dev Only callable by the owner.
     */
    function registerSelector(
        bytes4 selector,
        uint256 offset
    ) external onlyOwner {
        _registerSelector(selector, offset);
    }

    /**
     * @param selector The function selector to remove from the whitelist
     * @notice Removes a function selector from the whitelist and resets its offset.
     * Emits SelectorRemoved event.
     * @dev Only callable by the owner.
     */
    function removeSelector(bytes4 selector) external onlyOwner {
        isSelectorSupported[selector] = false;
        functionAddressOffsets[selector] = 0;
        emit SelectorRemoved(selector);
    }

    /**
     * @param target The contract address to call
     * @param value The ETH value to send with the call
     * @param data The calldata to execute on the target (signed by owner/adgent)
     * @param signature The ECDSA signature over (target, value, data, nonce, chainId)
     * @notice Executes a meta-transaction. Anyone can call this, but the
     * signature must come from the owner or the adgent.
     * Flow: 1) verify signature → 2) security checks → 3) execute → 4) increment nonce
     * @dev Reverts if paused, target not whitelisted, selector not whitelisted,
     * recipient invalid, or signature invalid.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) external PauseCheck {
        // 1. Verify signature — owner OR adgent must have signed
        if (signature.length != 65) {
            revert MinimalAccount__InvalidSignatureLength();
        }

        bytes32 hash = keccak256(
            abi.encode(
                target,
                value,
                keccak256(data),
                nonce,
                block.chainid
            )
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(hash);
        address signer = ECDSA.recover(ethSignedHash, signature);

        if (signer != owner() && signer != _adgent) {
            revert MinimalAccount__InvalidSignature();
        }

        // 2. Security checks + execute
        uint256 currentNonce = nonce;
        _validateAndExecute(target, value, data);

        emit Executed(target, value, _getSelector(data), signer, currentNonce);
    }

    /**
     * @param targets Array of contract addresses to call
     * @param values Array of ETH values to send with each call
     * @param datas Array of calldata to execute on each target
     * @param signature The ECDSA signature over the batch hash
     * @notice Executes multiple meta-transactions in a single call (all-or-nothing).
     * The signature covers the entire batch: hash of all targets, values, datas,
     * the start nonce, and chainId. The nonce increments per operation.
     * @dev Reverts if any operation fails (atomic). Same security checks as execute.
     */
    function batchExecute(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes calldata signature
    ) external PauseCheck {
        // 0. Validate array lengths match
        uint256 len = targets.length;
        if (len != values.length || len != datas.length) {
            revert MinimalAccount__BatchLengthMismatch();
        }

        // 1. Verify signature over the entire batch
        if (signature.length != 65) {
            revert MinimalAccount__InvalidSignatureLength();
        }

        // Hash each data element and pack into a single hash
        bytes32[] memory dataHashes = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            dataHashes[i] = keccak256(datas[i]);
        }

        bytes32 batchHash = keccak256(
            abi.encode(
                targets,
                values,
                dataHashes,
                nonce, // start nonce
                block.chainid
            )
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(batchHash);
        address signer = ECDSA.recover(ethSignedHash, signature);

        if (signer != owner() && signer != _adgent) {
            revert MinimalAccount__InvalidSignature();
        }

        // 2. Execute each operation with full security checks
        uint256 startNonce = nonce;
        for (uint256 i = 0; i < len; i++) {
            _validateAndExecute(targets[i], values[i], datas[i]);
        }

        emit BatchExecuted(len, signer, startNonce);
    }

    // ////////////////////////////////////////
    // /////////// INTERNAL FUNCTIONS /////////
    // ////////////////////////////////////////

    /**
     * @param selector The function selector to register
     * @param offset The byte offset of the recipient address within calldata
     * @notice Internal helper to register a selector with its offset.
     * Emits SelectorRegistered event.
     */
    function _registerSelector(bytes4 selector, uint256 offset) internal {
        functionAddressOffsets[selector] = offset;
        isSelectorSupported[selector] = true;
        emit SelectorRegistered(selector, offset);
    }

    /**
     * @param target The contract address to register as allowed target
     * @notice Internal helper to register a target.
     * Emits TargetRegistered event.
     */
    function _registerTarget(address target) internal {
        isAllowedTarget[target] = true;
        emit TargetRegistered(target);
    }

    /**
     * @param recipient The address to authorize as allowed recipient/spender
     * @notice Internal helper to set allowed address.
     */
    function _setAllowedAddress(address recipient) internal {
        isAllowedAddress[recipient] = true;
    }

    /**
     * @param target The contract address to call
     * @param value The ETH value to send
     * @param data The calldata to execute
     * @notice Internal helper that runs all security checks and executes a single call.
     * Used by both execute and batchExecute to avoid stack-too-deep.
     */
    function _validateAndExecute(
        address target,
        uint256 value,
        bytes calldata data
    ) internal {
        // Check target whitelist
        if (isAllowedTarget[target] == false) {
            revert TargetNotRegistered(target);
        }

        // Extract selector
        bytes4 innerSelector;
        assembly {
            innerSelector := calldataload(data.offset)
        }

        // Check selector whitelist
        if (isSelectorSupported[innerSelector] == false) {
            revert SelectorNotRegistered(innerSelector);
        }

        // Validate recipient
        uint256 addressOffset = functionAddressOffsets[innerSelector];
        address recipient = _extractRecipientFromMemory(data, addressOffset);
        if (recipient != address(this)) {
            if (!isAllowedAddress[recipient]) {
                revert RecipientInvalido(
                    addressOffset,
                    innerSelector,
                    recipient,
                    address(this)
                );
            }
        }

        // Increment nonce (CEI)
        nonce++;

        // Execute call
        (bool success, bytes memory result) = target.call{
            value: value,
            gas: gasleft()
        }(data);
        if (!success) {
            revert MinimalAccount__CallFailed(result);
        }
    }

    /**
     * @param data The calldata to extract the selector from
     * @return The first 4 bytes of data as a bytes4 selector
     * @notice Internal helper to extract selector from calldata.
     */
    function _getSelector(bytes calldata data) internal pure returns (bytes4) {
        bytes4 selector;
        assembly {
            selector := calldataload(data.offset)
        }
        return selector;
    }

    /**
     * @param data The calldata (including 4-byte selector prefix)
     * @param addressOffset The byte offset to read from (base 36)
     * @return extractedAddress The address extracted at the given offset
     * @notice Extracts an address from calldata at a specific offset.
     * Base offset is 36 bytes (32 bytes length prefix + 4 bytes selector).
     * offset 0 = word 0 (first parameter after selector).
     */
    function _extractRecipientFromMemory(
        bytes memory data,
        uint256 addressOffset
    ) internal pure returns (address extractedAddress) {
        assembly {
            // Base de 36 bytes (32 len + 4 selector)
            // Con base 36, offset 0 = word 0 (primer param despues del selector)
            let rawWord := mload(add(add(data, 36), addressOffset))

            // Mascara de 160 bits (20 bytes) para la direccion
            extractedAddress := and(
                rawWord,
                0xffffffffffffffffffffffffffffffffffffffff
            )
        }
    }

    // ////////////////////////////////////////
    // ///////// VIEW & PURE FUNCTIONS ////////
    // ////////////////////////////////////////

    /**
     * @return The address of the authorized adgent
     * @notice Returns the current adgent address.
     */
    function getAdgent() external view returns (address) {
        return _adgent;
    }

    /**
     * @return The current pause state
     * @notice Returns true if the contract is paused.
     */
    function getPause() external view returns (bool) {
        return _pause;
    }

}
