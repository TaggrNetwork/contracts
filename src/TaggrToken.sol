// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.37;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title TAGGR
/// @notice TAGGR on Ethereum L1: an immutable ERC20 with a role-based minter
///         and a two-step controller role.
/// @dev Supply enters only through the minter: directly (`mint`) or through
///      EIP-712 recipes (`mintWithAuthorization`) issued by whoever holds the
///      minter role (the Taggr canister in the phase-1 deployment, 1:1 with
///      IC burns). Supply leaves only through `burn`, which burns the caller's
///      own tokens. There is no proxy, pause, fees or admin escape hatch. The
///      controller role can be handed over through a signed nomination
///      (`nominateControllerWithAuthorization`), reserved for the later
///      transfer of control to L1; it is protected by a nomination nonce that
///      moves on every nomination and every controller change, so a signature
///      is valid at most once.
contract TaggrToken is ERC20, EIP712 {
    /// @notice Hard cap in wei (1 TAGGR = 1e18 wei; 1 IC base unit = 1e16 wei).
    uint256 public constant MAX_SUPPLY = 1_000_000e18;

    /// @notice EIP-712 typehash of a mint recipe.
    bytes32 public constant MINT_TYPEHASH = keccak256("Mint(address to,uint256 amount,uint256 index)");

    /// @notice EIP-712 typehash of a controller nomination.
    bytes32 public constant NOMINATE_CONTROLLER_TYPEHASH =
        keccak256("NominateController(address candidate,uint256 nonce)");

    /// @notice Root role: sets the minter and starts controller handovers.
    address public controller;

    /// @notice Nominee of the pending two-step controller handover.
    address public pendingController;

    /// @notice Generation of the controller role: bumped by every nomination and
    ///         by every completed handover, so a nomination signature is single
    ///         use and dies with the generation it was signed for.
    uint256 public nominationNonce;

    /// @notice Minter: signs mint recipes.
    address public minter;

    /// @dev Mint recipe bitmask: one slot holds 256 recipes (`index >> 8`). The
    ///      index space is monotonic and owned by the minter, which assigns
    ///      indices as it issues recipes. Controller nominations do not use it.
    mapping(uint256 slot => uint256 used) private _usedRecipes;

    event MinterChanged(address indexed previousMinter, address indexed newMinter);
    event ControllerNominated(address indexed pendingController);
    event ControllerChanged(address indexed previousController, address indexed newController);

    error NotMinter();
    error NotController();
    error NotPendingController();
    error RecipeAlreadyUsed(uint256 index);
    error StaleNominationNonce(uint256 provided, uint256 expected);
    error SupplyCapExceeded();
    error InvalidSigner(address expected);

    /// @param initialMinter Initial minter (the Taggr canister EOA in the
    ///        phase-1 deployment).
    /// @param initialController Initial controller (the same canister EOA in
    ///        the phase-1 deployment).
    /// @dev Zero addresses are not rejected: a zero minter can be replaced by
    ///      the controller, but a zero controller permanently disables role
    ///      changes.
    constructor(address initialMinter, address initialController) ERC20("TAGGR", "TAGGR") EIP712("TAGGR", "1") {
        minter = initialMinter;
        controller = initialController;
        emit MinterChanged(address(0), initialMinter);
        emit ControllerChanged(address(0), initialController);
    }

    /// @notice Mints directly. Only the current minter can call this; in the
    ///         phase-1 setup new supply normally flows through
    ///         `mintWithAuthorization`.
    function mint(address to, uint256 amount) external {
        if (msg.sender != minter) revert NotMinter();
        if (amount > MAX_SUPPLY - totalSupply()) revert SupplyCapExceeded();
        _mint(to, amount);
    }

    /// @notice Burns `amount` tokens from the caller. Self-burn only: supply
    ///         decreases and a `Transfer(caller, address(0), amount)` event is
    ///         emitted, so explorers and indexers account for it.
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /// @notice Sets the minter. Only the controller can call this.
    function setMinter(address newMinter) external {
        if (msg.sender != controller) revert NotController();
        emit MinterChanged(minter, newMinter);
        minter = newMinter;
    }

    /// @notice Starts a controller handover. Only the controller can call
    ///         this. A pending nomination is replaced.
    function nominateController(address candidate) external {
        if (msg.sender != controller) revert NotController();
        // Invalidates any signed nomination that is still outstanding.
        nominationNonce += 1;
        pendingController = candidate;
        emit ControllerNominated(candidate);
    }

    /// @notice Completes a controller handover. Only the nominee can call
    ///         this; a contract nominee calls through its own code.
    function acceptController() external {
        if (msg.sender != pendingController) revert NotPendingController();
        emit ControllerChanged(controller, msg.sender);
        controller = msg.sender;
        // Clearing the pending slot is covered by ControllerChanged above.
        // forge-lint: disable-next-line(missing-events-access-control)
        pendingController = address(0);
        // Anything signed by the previous controller is now stale.
        nominationNonce += 1;
    }

    /// @notice Executes a minter-signed mint recipe. Anyone may relay it; the
    ///         recipient and amount are fixed by the recipe.
    /// @param index Recipe index assigned by the signer.
    /// @param signature 65-byte low-s `r || s || v` EIP-712 signature of the
    ///        current minter over `mintDigest(to, amount, index)`.
    function mintWithAuthorization(address to, uint256 amount, uint256 index, bytes calldata signature) external {
        if (_recipeUsed(index)) revert RecipeAlreadyUsed(index);
        if (ECDSA.recover(_mintDigest(to, amount, index), signature) != minter) revert InvalidSigner(minter);
        if (amount > MAX_SUPPLY - totalSupply()) revert SupplyCapExceeded();
        _useRecipe(index);
        _mint(to, amount);
    }

    /// @notice Executes a controller-signed controller nomination.
    ///         Anyone may relay it; the candidate and the nonce are fixed by
    ///         the signature. Exists so a controller that cannot send
    ///         transactions itself (like the canister EOA) can still hand
    ///         control over; reserved for the later transfer of control to L1.
    /// @param nonce Current `nominationNonce`, i.e. the generation the
    ///        signature was produced for.
    /// @param signature 65-byte low-s `r || s || v` EIP-712 signature of the
    ///        current controller over `nominateControllerDigest(candidate, nonce)`.
    function nominateControllerWithAuthorization(address candidate, uint256 nonce, bytes calldata signature) external {
        if (nonce != nominationNonce) revert StaleNominationNonce(nonce, nominationNonce);
        if (ECDSA.recover(_nominateControllerDigest(candidate, nonce), signature) != controller) {
            revert InvalidSigner(controller);
        }
        nominationNonce = nonce + 1;
        pendingController = candidate;
        // ECDSA.recover above is internal and pure; the token makes no
        // external calls, so there is no reentrancy surface here.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ControllerNominated(candidate);
    }

    /// @notice EIP-712 digest that the current minter signs for
    ///         `mintWithAuthorization`.
    function mintDigest(address to, uint256 amount, uint256 index) external view returns (bytes32) {
        return _mintDigest(to, amount, index);
    }

    /// @notice EIP-712 digest that the current controller signs for
    ///         `nominateControllerWithAuthorization`.
    function nominateControllerDigest(address candidate, uint256 nonce) external view returns (bytes32) {
        return _nominateControllerDigest(candidate, nonce);
    }

    function _mintDigest(address to, uint256 amount, uint256 index) private view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MINT_TYPEHASH, to, amount, index)));
    }

    function _nominateControllerDigest(address candidate, uint256 nonce) private view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(NOMINATE_CONTROLLER_TYPEHASH, candidate, nonce)));
    }

    /// @notice True if the mint recipe index has been consumed.
    function recipeUsed(uint256 index) external view returns (bool) {
        return _recipeUsed(index);
    }

    function _recipeUsed(uint256 index) private view returns (bool) {
        return (_usedRecipes[index >> 8] & (uint256(1) << (index & 0xff))) != 0;
    }

    function _useRecipe(uint256 index) private {
        _usedRecipes[index >> 8] |= uint256(1) << (index & 0xff);
    }
}
