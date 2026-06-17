// SPDX-License-Identifier: UNLICENSED
/**
 * @title Security Reporting
 * @notice If you discover any security vulnerabilities, please report them responsibly.
 * @contact email: security@concero.io
 */
pragma solidity 0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IValidatorLib} from "../../interfaces/IValidatorLib.sol";
import {ValidatorCodec} from "../../common/libraries/ValidatorCodec.sol";
import {IConceroRouter} from "../../interfaces/IConceroRouter.sol";

/// @title EcdsaValidatorLib
/// @notice Base implementation of an ECDSA-based validator library for Concero.
/// @dev
/// - Implements `IValidatorLib` and verifies messages using multiple ECDSA signatures.
/// - Enforces:
///   * a minimum number of distinct allowed signers,
///   * per-destination-chain gas limits used for validator config.
/// - Child contracts must implement `_extractSignaturesAndHash` and `_checkValidation`.
abstract contract EcdsaValidatorLib is IValidatorLib {
    using ECDSA for bytes32;

    /// @notice Thrown when the number of provided signatures is below the required threshold.
    /// @param received Number of signatures received.
    /// @param expected Minimum number of signatures required.
    error InvalidSignaturesCount(uint256 received, uint256 expected);
    /// @notice Thrown when the same signer appears more than once in the signature set.
    /// @param signer Address of the duplicated signer.
    error DuplicateSigner(address signer);
    error InvalidSigner(address signer);
    error InvalidSignersCount(uint256 signersCount, uint256 isAllowedArrLength);
    error LengthMismatch(uint256, uint256);
    error InvalidSignatureLength(uint256 received, uint256 expected);

    uint8 internal constant SIGNATURE_LENGTH = 65;

    mapping(address signer => bool isAllowed) internal s_isSignerAllowed;
    mapping(uint24 => uint32 dstChainGasLimit) internal s_dstChainGasLimits;
    uint8 internal s_minSignersCount;
    uint256[47] private __gap;

    // VIEW FUNCTION //

    /// @inheritdoc IValidatorLib
    /// @dev
    /// - Returns an EVM validator config containing the gas limit for the destination chain
    ///   specified in `messageRequest.dstChainSelector`.
    /// - Uses `ValidatorCodec.encodeEvmConfig`.
    /// @param messageRequest Message request from which the destination chain selector is taken.
    /// @return Encoded EVM validator configuration (version + type + gasLimit).
    function getValidatorConfig(
        IConceroRouter.MessageRequest calldata messageRequest
    ) public view virtual returns (bytes memory) {
        return ValidatorCodec.encodeEvmConfig(s_dstChainGasLimits[messageRequest.dstChainSelector]);
    }

    /// @inheritdoc IValidatorLib
    /// @dev
    /// - Decodes and verifies signatures using `_verifySignatures`.
    /// - Performs any additional validation logic in `_checkValidation`.
    /// - Returns true only if both signature verification and additional checks succeed.
    /// @param messageReceipt Packed Concero message receipt.
    /// @param validation Validator-specific data containing signatures (and possibly other data).
    /// @return True if validation is successful, false otherwise.
    function isValid(
        bytes calldata messageReceipt,
        bytes calldata validation
    ) external view override returns (bool) {
        _verifySignatures(validation);
        return _checkValidation(messageReceipt, validation);
    }

    /// @notice Returns whether a given signer is currently allowed.
    /// @param signer Address of the signer to check.
    /// @return True if the signer is allowed, false otherwise.
    function isSignerAllowed(address signer) external view returns (bool) {
        return s_isSignerAllowed[signer];
    }

    /// @notice Returns the configured minimum number of signers required for validation.
    /// @return Minimum number of distinct allowed signers.
    function getMinSignersCount() external view returns (uint8) {
        return s_minSignersCount;
    }

    /// @notice Returns the EVM gas limit configured for a given destination chain selector.
    /// @param chainSelector Destination chain selector.
    /// @return Gas limit used by this validator for that chain.
    function getDstChainGasLimit(uint24 chainSelector) public view returns (uint32) {
        return s_dstChainGasLimits[chainSelector];
    }

    /// @notice Returns the EVM gas limits configured for multiple destination chain selectors.
    /// @param chainSelectors Array of destination chain selectors.
    /// @return Array of gas limits corresponding to each provided chain selector.
    function getGasLimitsForChains(
        uint24[] calldata chainSelectors
    ) external view returns (uint32[] memory) {
        uint32[] memory gasLimits = new uint32[](chainSelectors.length);

        for (uint256 i; i < chainSelectors.length; ++i) {
            gasLimits[i] = s_dstChainGasLimits[chainSelectors[i]];
        }

        return gasLimits;
    }

    // INTERNAL FUNCTIONS

    /// @notice Verifies that a given validation blob contains enough valid, distinct signatures.
    /// @dev
    /// - Calls `_extractSignaturesAndHash` to parse the blob into:
    ///   * `signatures[]`: raw signature bytes,
    ///   * `hash`: digest that must be signed.
    /// - Checks:
    ///   * `signatures.length >= s_minSignersCount`,
    ///   * each recovered signer is allowed (`s_isSignerAllowed[signer] == true`),
    ///   * no signer appears more than once (no duplicates).
    /// - Reverts with:
    ///   * `InvalidSignaturesCount` if not enough signatures,
    ///   * `InvalidSigner` if a signer is not allowed,
    ///   * `DuplicateSigner` if the same signer appears multiple times.
    /// @param validation Encoded validation data containing signatures and any auxiliary info.
    function _verifySignatures(bytes calldata validation) internal view {
        (bytes[] memory signatures, bytes32 hash) = _extractSignaturesAndHash(validation);

        require(
            signatures.length >= s_minSignersCount,
            InvalidSignaturesCount(signatures.length, s_minSignersCount)
        );

        address[] memory signers = new address[](signatures.length);

        for (uint256 i; i < signatures.length; ++i) {
            address signer = _recoverSigner(signatures[i], hash);
            require(s_isSignerAllowed[signer], InvalidSigner(signer));
            for (uint256 k; k < i; ++k) {
                require(signer != signers[k], DuplicateSigner(signer));
            }
            signers[i] = signer;
        }
    }

    /// @notice Recovers the signer address from a signature and message hash.
    /// @dev
    /// - Normalize v to the standard 27/28 range
    ///   * If v < 2, - add 27 to normalize
    ///   * If v >= 35, it is an EIP-155 format - extract recovery ID and normalize to 27/28
    ///   * Otherwise, v is already 27/28 (standard format), leave unchanged
    /// - Uses OpenZeppelin's `ECDSA.recover` under the hood.
    /// @param signature Raw ECDSA signature bytes.
    /// @param hash Message hash that was signed (already prefixed if required).
    /// @return Address of the recovered signer.
    function _recoverSigner(
        bytes memory signature,
        bytes32 hash
    ) internal pure virtual returns (address) {
        require(
            signature.length == SIGNATURE_LENGTH,
            InvalidSignatureLength(signature.length, SIGNATURE_LENGTH)
        );

        uint8 v = uint8(signature[64]);

        if (v < 2) {
            signature[64] = bytes1(v + 27);
        } else if (v >= 35) {
            uint8 recoveryId = uint8((v - 35) % 2);
            signature[64] = bytes1(recoveryId + 27);
        }

        return hash.recover(signature);
    }

    /// @notice Internal helper to configure allowed signers in batch.
    /// @dev
    /// - `signers` and `isAllowedArr` must have the same length.
    /// - Reverts with `InvalidSignersCount` on length mismatch.
    /// @param signers Addresses of signers to configure.
    /// @param isAllowedArr Flags indicating whether each signer is allowed.
    function _setAllowedSigners(address[] calldata signers, bool[] calldata isAllowedArr) internal {
        require(
            signers.length == isAllowedArr.length,
            InvalidSignersCount(signers.length, isAllowedArr.length)
        );

        for (uint256 i; i < signers.length; ++i) {
            s_isSignerAllowed[signers[i]] = isAllowedArr[i];
        }
    }

    function _setMinSignersCount(uint8 expectedSignersCount) internal {
        s_minSignersCount = expectedSignersCount;
    }

    // @notice Internal helper to configure gas limits per destination chain.
    /// @dev
    /// - `dstChainSelectors` and `gasLimits` must have the same length.
    /// - Reverts with `LengthMismatch` on length mismatch.
    /// @param dstChainSelectors Array of destination chain selectors.
    /// @param gasLimits Array of gas limits associated with each chain selector.
    function _setDstChainGasLimits(
        uint24[] calldata dstChainSelectors,
        uint32[] calldata gasLimits
    ) internal {
        require(
            dstChainSelectors.length == gasLimits.length,
            LengthMismatch(dstChainSelectors.length, gasLimits.length)
        );

        for (uint256 i; i < dstChainSelectors.length; ++i) {
            s_dstChainGasLimits[dstChainSelectors[i]] = gasLimits[i];
        }
    }

    /// @notice Extracts signatures and the signed hash from a validation blob.
    /// @dev
    /// - Must be implemented by derived contracts, since the blob layout is scheme-specific.
    /// - Expected to return:
    ///   * `signatures`: array of signature bytes,
    ///   * `hash`: message hash that each signature must validate.
    /// @param validation Encoded validation data.
    /// @return signatures Array of signature byte arrays.
    /// @return hash Message hash to be verified against signatures.
    function _extractSignaturesAndHash(
        bytes calldata validation
    ) internal view virtual returns (bytes[] memory, bytes32);

    /// @notice Performs additional validation logic beyond signature checks.
    /// @dev
    /// - Must be implemented by derived contracts.
    /// - Typical responsibilities:
    ///   * check chain selector,
    ///   * check nonce / replay protection,
    ///   * verify message structure or additional metadata.
    /// @param messageReceipt Packed Concero message receipt.
    /// @param validation Validation data (same as passed to `_verifySignatures`).
    /// @return True if the validation logic considers the message valid, false otherwise.
    function _checkValidation(
        bytes calldata messageReceipt,
        bytes calldata validation
    ) internal view virtual returns (bool);
}
