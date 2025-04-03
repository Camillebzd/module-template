// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import {ERC7579ValidatorBase} from "modulekit/Modules.sol";
import {PackedUserOperation} from "modulekit/external/ERC4337.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {SentinelList4337Lib, SENTINEL, WebAuthnValidatorData} from "./SentinelList4337New.sol";
import {LibSort} from "solady/utils/LibSort.sol";
import {CheckSignatures} from "checknsignatures/CheckNSignatures.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {WebAuthn} from "./WebAuthn.sol";

uint256 constant TYPE_STATELESS_VALIDATOR = 7;
/**
 * @title WebAuthnOwnableValidator
 * @dev Module that allows users to designate user owners that can validate transactions using a
 * threshold. The owners use the P256 curve to validate signatures.
 * @author Rhinestone & Camille
 */

contract WebAuthnOwnableValidator is ERC7579ValidatorBase {
    using LibSort for *;
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;

    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    event ModuleInitialized(address indexed account);
    event ModuleUninitialized(address indexed account);
    event ThresholdSet(address indexed account, uint256 threshold);
    event WebAuthnPublicKeyRegistered(
        address indexed account,
        bytes32 indexed authenticatorIdHash,
        uint256 pubKeyX,
        uint256 pubKeyY
    );
    event WebAuthnPublicKeyRemoved(
        address indexed account,
        bytes32 indexed authenticatorIdHash
    );

    error ThresholdNotSet();
    error InvalidThreshold();
    error NotSortedAndUnique();
    error MaxOwnersReached();
    error InvalidOwner(address owner);
    error InvalidAuthenticatorIdHash(bytes32 authenticatorIdHash);
    error CannotRemoveOwner();
    error InvalidPublicKey();

    // maximum number of owners per account
    uint256 constant MAX_OWNERS = 32;

    // account => authenticatorIdHash (=> WebAuthnValidatorData)
    SentinelList4337Lib.SentinelList owners;
    // account => threshold
    mapping(address account => uint256) public threshold;
    // account => ownerCount
    mapping(address => uint256) public ownerCount;

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Initializes the module with the threshold and WebAuthnValidatorData
     * @dev data is encoded as follows: abi.encode(threshold, WebAuthnValidatorData)
     *
     * @param data encoded data containing the threshold and WebAuthnValidatorData
     */
    function onInstall(bytes calldata data) external override {
        // Check if the module is already initialized?
        require(!isInitialized(msg.sender), "Module already initialized");

        // Decode the threshold, WebAuthnValidatorData array, and authenticatorIdHashes
        (
            uint256 _threshold,
            WebAuthnValidatorData[] memory webAuthnDataArray,
            bytes32[] memory authenticatorIdHashes
        ) = abi.decode(data, (uint256, WebAuthnValidatorData[], bytes32[]));

        // Ensure the arrays are of the same length
        require(
            webAuthnDataArray.length == authenticatorIdHashes.length,
            "Mismatched data lengths"
        );

        // Check validity of each public key
        for (uint256 i = 0; i < webAuthnDataArray.length; i++) {
            WebAuthnValidatorData memory webAuthnData = webAuthnDataArray[i];
            if (webAuthnData.pubKeyX == 0 || webAuthnData.pubKeyY == 0) {
                revert InvalidPublicKey();
            }
        }

        // TODO check that the authenticatorIdHashes are unique
        // check that owners are sorted and uniquified
        if (!authenticatorIdHashes.isSortedAndUniquified()) {
            revert NotSortedAndUnique();
        }

        // make sure the threshold is set
        if (_threshold == 0) {
            revert ThresholdNotSet();
        }

        // make sure the threshold is less than the number of authenticatorIdHashes
        uint256 authenticatorIdHashesLength = authenticatorIdHashes.length;
        if (authenticatorIdHashesLength < _threshold) {
            revert InvalidThreshold();
        }

        // cache the account address
        address account = msg.sender;

        // set threshold
        threshold[account] = _threshold;

        // check if max owners is reached
        if (authenticatorIdHashesLength > MAX_OWNERS) {
            revert MaxOwnersReached();
        }

        // set owner count
        ownerCount[account] = authenticatorIdHashesLength;

        // initialize the owner list
        owners.init(account);

        // add owners to the list
        for (uint256 i = 0; i < authenticatorIdHashesLength; i++) {
            bytes32 authenticatorIdHash = authenticatorIdHashes[i];
            if (authenticatorIdHash == bytes32(0)) {
                revert InvalidAuthenticatorIdHash(authenticatorIdHash);
            }
            owners.push(account, authenticatorIdHash, webAuthnDataArray[i]);
            emit WebAuthnPublicKeyRegistered(
                account,
                authenticatorIdHash,
                webAuthnDataArray[i].pubKeyX,
                webAuthnDataArray[i].pubKeyY
            );
        }

        emit ModuleInitialized(account);
    }

    /**
     * Handles the uninstallation of the module and clears the threshold and owners
     * @dev the data parameter is not used
     */
    function onUninstall(bytes calldata) external override {
        // cache the account address
        address account = msg.sender;

        // clear the owners
        owners.popAll(account);

        // remove the threshold
        threshold[account] = 0;

        // remove the owner count
        ownerCount[account] = 0;

        emit ModuleUninitialized(account);
    }

    /**
     * Checks if the module is initialized
     *
     * @param smartAccount address of the smart account
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address smartAccount) public view returns (bool) {
        return threshold[smartAccount] != 0;
    }

    /**
     * Sets the threshold for the account
     * @dev the function will revert if the module is not initialized
     *
     * @param _threshold uint256 threshold to set
     */
    function setThreshold(uint256 _threshold) external {
        // cache the account address
        address account = msg.sender;
        // check if the module is initialized and revert if it is not
        if (!isInitialized(account)) revert NotInitialized(account);

        // make sure that the threshold is set
        if (_threshold == 0) {
            revert InvalidThreshold();
        }

        // make sure the threshold is less than the number of owners
        if (ownerCount[account] < _threshold) {
            revert InvalidThreshold();
        }

        // set the threshold
        threshold[account] = _threshold;

        emit ThresholdSet(account, _threshold);
    }

    /**
     * Adds an owner to the account
     * @dev will revert if the owner is already added
     *
     * @param _data authenticatorIdHash and public key encoded as `abi.encode(authenticatorIdHash, WebAuthnValidatorData)`
     */
    function addOwner(bytes calldata _data) external {
        // cache the account address
        address account = msg.sender;
        // check if the module is initialized and revert if it is not
        if (!isInitialized(account)) revert NotInitialized(account);

        // check validity of the public key
        (
            WebAuthnValidatorData memory webAuthnData,
            bytes32 authenticatorIdHash
        ) = abi.decode(_data, (WebAuthnValidatorData, bytes32));
        if (webAuthnData.pubKeyX == 0 || webAuthnData.pubKeyY == 0) {
            revert InvalidPublicKey();
        }

        // cache owner count
        uint256 count = ownerCount[account];

        // check if max owners is reached
        if (count >= MAX_OWNERS) {
            revert MaxOwnersReached();
        }

        // increment the owner count
        ownerCount[account]++;

        // add the owner to the list
        owners.push(account, authenticatorIdHash, webAuthnData);

        emit WebAuthnPublicKeyRegistered(
            msg.sender,
            authenticatorIdHash,
            webAuthnData.pubKeyX,
            webAuthnData.pubKeyY
        );
    }

    /**
     * Removes an owner from the account
     * @dev will revert if the owner is not added or the previous owner is invalid
     *
     * @param prevOwner address of the previous owner
     * @param owner address of the owner to remove
     */
    function removeOwner(bytes32 prevOwner, bytes32 owner) external {
        // cache the account address
        address account = msg.sender;

        // check if an owner can be removed
        if (ownerCount[account] == threshold[account]) {
            // if the owner count is equal to the threshold, revert
            // this means that removing an owner would make the threshold unreachable
            revert CannotRemoveOwner();
        }

        // remove the owner
        owners.pop(account, prevOwner, owner);

        // decrement the owner count
        ownerCount[account]--;

        emit WebAuthnPublicKeyRemoved(account, owner);
    }

    /**
     * Returns the owners of the account
     *
     * @param account address of the account
     *
     * @return ownersArray array of owners
     */
    function getOwners(
        address account
    ) external view returns (bytes32[] memory ownersArray) {
        // get the owners from the linked list
        (ownersArray, ) = owners.getEntriesPaginated(
            account,
            SENTINEL,
            MAX_OWNERS
        );
    }

    // TODO Create a function to retrieve the public key of an owner

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Validates a user operation
     *
     * @param userOp PackedUserOperation struct containing the UserOperation
     * @param userOpHash bytes32 hash of the UserOperation
     *
     * @return ValidationData the UserOperation validation result
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external view override returns (ValidationData) {
        // validate the signature with the config
        bool isValid = _validateSignatureWithConfig(
            userOp.sender,
            userOpHash,
            userOp.signature
        );

        // return the result
        if (isValid) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /**
     * Validates an ERC-1271 signature with the sender
     *
     * @param hash bytes32 hash of the data
     * @param data bytes data containing the signatures
     *
     * @return bytes4 EIP1271_SUCCESS if the signature is valid, EIP1271_FAILED otherwise
     */
    function isValidSignatureWithSender(
        address,
        bytes32 hash,
        bytes calldata data
    ) external view override returns (bytes4) {
        // validate the signature with the config
        bool isValid = _validateSignatureWithConfig(msg.sender, hash, data);

        // return the result
        if (isValid) {
            return EIP1271_SUCCESS;
        }
        return EIP1271_FAILED;
    }

    /**
     * Validates a signature with the data (stateless validation)
     *
     * @param hash bytes32 hash of the data
     * @param signature bytes data containing the signatures
     * @param data bytes data containing the data
     *
     * @return bool true if the signature is valid, false otherwise
     */
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    ) external view returns (bool) {
        // decode the threshold and owners
        // (uint256 _threshold, address[] memory _owners) = abi.decode(
        //     data,
        //     (uint256, address[])
        // );

        // // check that owners are sorted and uniquified
        // if (!_owners.isSortedAndUniquified()) {
        //     return false;
        // }

        // // check that threshold is set
        // if (_threshold == 0) {
        //     return false;
        // }

        // // recover the signers from the signatures
        // address[] memory signers = CheckSignatures.recoverNSignatures(
        //     ECDSA.toEthSignedMessageHash(hash),
        //     signature,
        //     _threshold
        // );

        // // sort and uniquify the signers to make sure a signer is not reused
        // signers.sort();
        // signers.uniquifySorted();

        // // check if the signers are owners
        // uint256 validSigners;
        // uint256 signersLength = signers.length;
        // for (uint256 i = 0; i < signersLength; i++) {
        //     (bool found, ) = _owners.searchSorted(signers[i]);
        //     if (found) {
        //         validSigners++;
        //     }
        // }

        // // check if the threshold is met and return the result
        // if (validSigners >= _threshold) {
        //     // if the threshold is met, return true
        //     return true;
        // }
        // // if the threshold is not met, false
        return false;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    function _validateSignatureWithConfig(
        address account,
        bytes32 hash,
        bytes calldata data
    ) internal view returns (bool) {
        // get the threshold and check that its set
        // uint256 _threshold = threshold[account];
        // if (_threshold == 0) {
        //     return false;
        // }

        // // recover the signers from the signatures
        // address[] memory signers = CheckSignatures.recoverNSignatures(
        //     ECDSA.toEthSignedMessageHash(hash),
        //     data,
        //     _threshold
        // );

        // // sort and uniquify the signers to make sure a signer is not reused
        // signers.sort();
        // signers.uniquifySorted();

        // // check if the signers are owners
        // uint256 validSigners;
        // uint256 signersLength = signers.length;
        // for (uint256 i = 0; i < signersLength; i++) {
        //     if (owners.contains(account, signers[i])) {
        //         validSigners++;
        //     }
        // }

        // // check if the threshold is met and return the result
        // if (validSigners >= _threshold) {
        //     // if the threshold is met, return true
        //     return true;
        // }
        // // if the threshold is not met, return false
        return false;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Returns the type of the module
     *
     * @param typeID type of the module
     *
     * @return true if the type is a module type, false otherwise
     */
    function isModuleType(
        uint256 typeID
    ) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    /**
     * Returns the name of the module
     *
     * @return name of the module
     */
    function name() external pure virtual returns (string memory) {
        return "WebAuthnOwnableValidator";
    }

    /**
     * Returns the version of the module
     *
     * @return version of the module
     */
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }
}
