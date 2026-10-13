// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TaggrToken} from "../src/TaggrToken.sol";

contract TaggrTokenTest is Test {
    uint256 internal constant MINTER_PK = 0xA11CE;
    uint256 internal constant CONTROLLER_PK = 0xC0FFEE;
    uint256 internal constant OTHER_PK = 0xBAD;
    uint256 internal constant SECP256K1N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    address internal minter;
    address internal controller;
    TaggrToken internal token;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event MinterChanged(address indexed previousMinter, address indexed newMinter);
    event ControllerNominated(address indexed nominee);
    event ControllerChanged(address indexed previousController, address indexed newController);

    function setUp() public {
        minter = vm.addr(MINTER_PK);
        controller = vm.addr(CONTROLLER_PK);
        token = new TaggrToken(minter, controller);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ---------------------------------------------------------------- setup --

    function testMetadataAndRoles() public view {
        assertEq(token.name(), "TAGGR");
        assertEq(token.symbol(), "TAGGR");
        assertEq(token.decimals(), 18);
        assertEq(token.MAX_SUPPLY(), 1e24);
        assertEq(token.totalSupply(), 0);
        assertEq(token.minter(), minter);
        assertEq(token.controller(), controller);
        assertEq(token.pendingController(), address(0));
    }

    function testConstructorEmitsRoleEvents() public {
        vm.expectEmit();
        emit MinterChanged(address(0), minter);
        vm.expectEmit();
        emit ControllerChanged(address(0), controller);
        new TaggrToken(minter, controller);
    }

    // ---------------------------------------------------------------- digest --

    function testEip712DomainFields() public view {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            token.eip712Domain();
        assertEq(name, "TAGGR");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(token));
    }

    function testMintDigestMatchesManualEip712() public view {
        address to = address(0xDEAD);
        uint256 amount = 123e18;
        uint256 index = 42;
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TAGGR")),
                keccak256(bytes("1")),
                block.chainid,
                address(token)
            )
        );
        bytes32 structHash =
            keccak256(abi.encode(keccak256("Mint(address to,uint256 amount,uint256 index)"), to, amount, index));
        assertEq(
            token.mintDigest(to, amount, index), keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
        );
    }

    function testNominateDigestMatchesManualEip712() public view {
        address candidate = address(0xDEAD);
        uint256 index = 42;
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TAGGR")),
                keccak256(bytes("1")),
                block.chainid,
                address(token)
            )
        );
        bytes32 structHash =
            keccak256(abi.encode(keccak256("NominateController(address candidate,uint256 index)"), candidate, index));
        assertEq(
            token.nominateControllerDigest(candidate, index),
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
        );
    }

    // ----------------------------------------------------------------- mint --

    function testMintOnlyMinter() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(TaggrToken.NotMinter.selector);
        token.mint(address(0xBEEF), 1e18);

        vm.prank(minter);
        token.mint(address(0xBEEF), 1e18);
        assertEq(token.balanceOf(address(0xBEEF)), 1e18);
        assertEq(token.totalSupply(), 1e18);
    }

    function testMintRespectsCap() public {
        uint256 cap = token.MAX_SUPPLY();
        vm.prank(minter);
        token.mint(minter, cap);
        assertEq(token.totalSupply(), cap);

        vm.prank(minter);
        vm.expectRevert(TaggrToken.SupplyCapExceeded.selector);
        token.mint(minter, 1);
    }

    function testMintWithAuthorizationHappyPath() public {
        address recipient = address(0xCAFE);
        uint256 amount = 5e18;
        uint256 index = 7;
        bytes memory signature = _sign(MINTER_PK, token.mintDigest(recipient, amount, index));

        vm.prank(address(0x1234)); // relayed by anyone
        vm.expectEmit();
        emit Transfer(address(0), recipient, amount);
        token.mintWithAuthorization(recipient, amount, index, signature);

        assertEq(token.balanceOf(recipient), amount);
        assertEq(token.totalSupply(), amount);
        assertTrue(token.recipeUsed(index));
    }

    function testWrongSignerDoesNotConsumeIndex() public {
        address recipient = address(0xCAFE);
        uint256 index = 9;
        bytes memory signature = _sign(OTHER_PK, token.mintDigest(recipient, 1e18, index));

        vm.expectRevert(abi.encodeWithSelector(TaggrToken.InvalidSigner.selector, minter));
        token.mintWithAuthorization(recipient, 1e18, index, signature);
        assertFalse(token.recipeUsed(index));

        bytes memory good = _sign(MINTER_PK, token.mintDigest(recipient, 1e18, index));
        token.mintWithAuthorization(recipient, 1e18, index, good);
        assertEq(token.balanceOf(recipient), 1e18);
    }

    function testRecipeReplayReverts() public {
        address recipient = address(0xCAFE);
        uint256 index = 11;
        bytes memory signature = _sign(MINTER_PK, token.mintDigest(recipient, 1e18, index));
        token.mintWithAuthorization(recipient, 1e18, index, signature);

        vm.expectRevert(abi.encodeWithSelector(TaggrToken.RecipeAlreadyUsed.selector, index));
        token.mintWithAuthorization(recipient, 1e18, index, signature);
    }

    function testRecipeBindsParameters() public {
        uint256 index = 13;
        bytes memory signature = _sign(MINTER_PK, token.mintDigest(address(0xCAFE), 1e18, index));

        vm.expectRevert(abi.encodeWithSelector(TaggrToken.InvalidSigner.selector, minter));
        token.mintWithAuthorization(address(0xBEEF), 1e18, index, signature);
    }

    function testHighSSignaturesRejected() public {
        uint256 index = 3;
        bytes32 digest = token.mintDigest(address(0xCAFE), 1e18, index);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MINTER_PK, digest);
        bytes32 highS = bytes32(SECP256K1N - uint256(s));
        uint8 flippedV = v == 27 ? uint8(28) : uint8(27);
        bytes memory malleable = abi.encodePacked(r, highS, flippedV);

        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureS.selector, highS));
        token.mintWithAuthorization(address(0xCAFE), 1e18, index, malleable);
        assertFalse(token.recipeUsed(index));
    }

    function testDigestBindsChainId() public {
        uint256 index = 1;
        vm.chainId(1);
        bytes memory signature = _sign(MINTER_PK, token.mintDigest(address(0xCAFE), 1e18, index));
        vm.chainId(31337);

        vm.expectRevert(abi.encodeWithSelector(TaggrToken.InvalidSigner.selector, minter));
        token.mintWithAuthorization(address(0xCAFE), 1e18, index, signature);
    }

    function testRecipesAcrossSlots() public {
        uint256[5] memory indices = [uint256(0), 255, 256, 511, 1000];
        for (uint256 i = 0; i < indices.length; i++) {
            uint256 index = indices[i];
            bytes memory signature = _sign(MINTER_PK, token.mintDigest(address(0xCAFE), 1, index));
            token.mintWithAuthorization(address(0xCAFE), 1, index, signature);
            assertTrue(token.recipeUsed(index));

            vm.expectRevert(abi.encodeWithSelector(TaggrToken.RecipeAlreadyUsed.selector, index));
            token.mintWithAuthorization(address(0xCAFE), 1, index, signature);
        }
        assertEq(token.balanceOf(address(0xCAFE)), 5);
    }

    function testMintWithAuthorizationRespectsCap() public {
        uint256 cap = token.MAX_SUPPLY();
        vm.prank(minter);
        token.mint(minter, cap - 1e18);

        uint256 index = 77;
        bytes memory signature = _sign(MINTER_PK, token.mintDigest(address(0xCAFE), 2e18, index));

        vm.expectRevert(TaggrToken.SupplyCapExceeded.selector);
        token.mintWithAuthorization(address(0xCAFE), 2e18, index, signature);
        assertFalse(token.recipeUsed(index));
    }

    // ------------------------------------------------------------- minter --

    function testSetMinterOnlyControllerAndRotates() public {
        address newMinter = address(0xD00D);

        vm.prank(minter);
        vm.expectRevert(TaggrToken.NotController.selector);
        token.setMinter(newMinter);

        vm.prank(controller);
        vm.expectEmit();
        emit MinterChanged(minter, newMinter);
        token.setMinter(newMinter);
        assertEq(token.minter(), newMinter);

        // Recipes signed by the previous minter no longer verify.
        uint256 index = 5;
        bytes memory staleSignature = _sign(MINTER_PK, token.mintDigest(address(0xCAFE), 1e18, index));
        vm.expectRevert(abi.encodeWithSelector(TaggrToken.InvalidSigner.selector, newMinter));
        token.mintWithAuthorization(address(0xCAFE), 1e18, index, staleSignature);
        assertFalse(token.recipeUsed(index));

        // The new minter can mint.
        vm.prank(newMinter);
        token.mint(address(0xCAFE), 1e18);
        assertEq(token.balanceOf(address(0xCAFE)), 1e18);
    }

    // --------------------------------------------------------- controller --

    function testControllerTwoStep() public {
        address candidate = address(0xABCD);

        vm.prank(minter);
        vm.expectRevert(TaggrToken.NotController.selector);
        token.nominateController(candidate);

        vm.prank(controller);
        vm.expectEmit();
        emit ControllerNominated(candidate);
        token.nominateController(candidate);
        assertEq(token.pendingController(), candidate);
        assertEq(token.controller(), controller);

        vm.prank(minter);
        vm.expectRevert(TaggrToken.NotPendingController.selector);
        token.acceptController();

        vm.prank(candidate);
        vm.expectEmit();
        emit ControllerChanged(controller, candidate);
        token.acceptController();
        assertEq(token.controller(), candidate);
        assertEq(token.pendingController(), address(0));

        // The previous controller lost its powers.
        vm.prank(controller);
        vm.expectRevert(TaggrToken.NotController.selector);
        token.nominateController(candidate);

        // The new controller can act.
        vm.prank(candidate);
        token.nominateController(minter);
        assertEq(token.pendingController(), minter);
    }

    function testNominationOverwritesPending() public {
        vm.startPrank(controller);
        token.nominateController(address(0x1));
        token.nominateController(address(0x2));
        vm.stopPrank();
        assertEq(token.pendingController(), address(0x2));
    }

    function testAcceptWithNoPendingReverts() public {
        vm.expectRevert(TaggrToken.NotPendingController.selector);
        token.acceptController();
    }

    function testNominateControllerWithAuthorization() public {
        address candidate = address(0xABCD);
        uint256 index = 100;
        bytes memory signature = _sign(CONTROLLER_PK, token.nominateControllerDigest(candidate, index));

        vm.prank(address(0x9999)); // relayed by anyone
        token.nominateControllerWithAuthorization(candidate, index, signature);
        assertEq(token.pendingController(), candidate);
        assertTrue(token.recipeUsed(index));

        vm.expectRevert(abi.encodeWithSelector(TaggrToken.RecipeAlreadyUsed.selector, index));
        token.nominateControllerWithAuthorization(candidate, index, signature);
    }

    function testNominateWithAuthorizationWrongSigner() public {
        address candidate = address(0xABCD);
        uint256 index = 101;
        bytes memory signature = _sign(MINTER_PK, token.nominateControllerDigest(candidate, index));

        vm.expectRevert(abi.encodeWithSelector(TaggrToken.InvalidSigner.selector, controller));
        token.nominateControllerWithAuthorization(candidate, index, signature);
        assertFalse(token.recipeUsed(index));
    }

    // ----------------------------------------------------------------- fuzz --

    function testFuzzRecipeIndex(uint256 index) public {
        bytes memory signature = _sign(MINTER_PK, token.mintDigest(address(0xCAFE), 1e18, index));
        token.mintWithAuthorization(address(0xCAFE), 1e18, index, signature);
        assertTrue(token.recipeUsed(index));

        vm.expectRevert(abi.encodeWithSelector(TaggrToken.RecipeAlreadyUsed.selector, index));
        token.mintWithAuthorization(address(0xCAFE), 1e18, index, signature);
    }

    function testFuzzMintCap(uint96 amount) public {
        uint256 cap = token.MAX_SUPPLY();
        vm.assume(amount <= cap);
        vm.prank(minter);
        token.mint(minter, amount);
        assertEq(token.totalSupply(), amount);

        if (amount < cap) {
            vm.prank(minter);
            vm.expectRevert(TaggrToken.SupplyCapExceeded.selector);
            token.mint(minter, cap - amount + 1);
        }
    }
}
