// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Sentinel address
bytes32 constant SENTINEL = bytes32(uint256(1));
bytes32 constant ZERO_HASH = bytes32(0x0);

struct WebAuthnValidatorData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

/**
 * @title SentinelListLib
 * @dev Library for managing a linked list of WebAuthnValidatorData structs
 * compliant with ERC-4337 validation rules
 * @author Rhinestone
 */
library SentinelList4337Lib {
    // Struct to hold the linked list
    struct SentinelList {
        mapping(bytes32 key => mapping(address account => bytes32 entry)) entries;
        mapping(bytes32 key => WebAuthnValidatorData) data;
    }

    error LinkedList_AlreadyInitialized();
    error LinkedList_InvalidPage();
    error LinkedList_InvalidEntry(bytes32 entry);
    error LinkedList_EntryAlreadyInList(bytes32 entry);

    /**
     * Initialize the linked list
     *
     * @param self The linked list
     * @param account The account to initialize the linked list for
     */
    function init(SentinelList storage self, address account) internal {
        if (alreadyInitialized(self, account))
            revert LinkedList_AlreadyInitialized();
        self.entries[SENTINEL][account] = SENTINEL;
    }

    /**
     * Check if the linked list is already initialized
     *
     * @param self The linked list
     * @param account The account to check if the linked list is initialized for
     *
     * @return bool True if the linked list is already initialized
     */
    function alreadyInitialized(
        SentinelList storage self,
        address account
    ) internal view returns (bool) {
        return self.entries[SENTINEL][account] != ZERO_HASH;
    }

    /**
     * Get the next entry in the linked list
     *
     * @param self The linked list
     * @param account The account to get the next entry for
     * @param entry The current entry
     *
     * @return bytes32 The next entry
     */
    function getNext(
        SentinelList storage self,
        address account,
        bytes32 entry
    ) internal view returns (bytes32) {
        if (entry == ZERO_HASH) {
            revert LinkedList_InvalidEntry(entry);
        }
        return self.entries[entry][account];
    }

    /**
     * Push a new entry to the linked list
     *
     * @param self The linked list
     * @param account The account to push the new entry for
     * @param newEntry The bytes representation of the new entry
     * @param dataEntry The data to store for the new entry
     */
    function push(
        SentinelList storage self,
        address account,
        bytes32 newEntry,
        WebAuthnValidatorData memory dataEntry
    ) internal {
        if (newEntry == ZERO_HASH || newEntry == SENTINEL) {
            revert LinkedList_InvalidEntry(newEntry);
        }
        if (self.entries[newEntry][account] != ZERO_HASH) {
            revert LinkedList_EntryAlreadyInList(newEntry);
        }

        // Link the new entry into the list
        self.entries[newEntry][account] = self.entries[SENTINEL][account];
        self.entries[SENTINEL][account] = newEntry;

        // Store the data for the new entry
        self.data[newEntry] = dataEntry;
    }

    /**
     * Safe push a new entry to the linked list
     * @dev This ensures that the linked list is initialized and initializes it if it is not
     *
     * @param self The linked list
     * @param account The account to push the new entry for
     * @param newEntry The new entry
     */
    // function safePush(
    //     SentinelList storage self,
    //     address account,
    //     WebAuthnValidatorData memory newEntry
    // ) internal {
    //     if (!alreadyInitialized(self, account)) {
    //         init({self: self, account: account});
    //     }
    //     push({self: self, account: account, newEntry: newEntry});
    // }

    /**
     * Pop an entry from the linked list
     *
     * @param self The linked list
     * @param account The account to pop the entry for
     * @param prevEntry The entry before the entry to pop
     * @param popEntry The entry to pop
     */
    function pop(
        SentinelList storage self,
        address account,
        bytes32 prevEntry,
        bytes32 popEntry
    ) internal {
        if (popEntry == ZERO_HASH || popEntry == SENTINEL) {
            revert LinkedList_InvalidEntry(prevEntry);
        }
        if (self.entries[prevEntry][account] != popEntry) {
            revert LinkedList_InvalidEntry(popEntry);
        }

        // Remove the entry from the list
        self.entries[prevEntry][account] = self.entries[popEntry][account];
        self.entries[popEntry][account] = ZERO_HASH;

        // Delete the data for the popped entry
        delete self.data[popEntry];
    }

    /**
     * Pop all entries from the linked list
     *
     * @param self The linked list
     * @param account The account to pop all entries for
     */
    function popAll(SentinelList storage self, address account) internal {
        bytes32 next = self.entries[SENTINEL][account]; // Start with the first entry after the sentinel
        while (next != ZERO_HASH && next != SENTINEL) {
            bytes32 current = next;
            next = self.entries[current][account]; // Move to the next entry
            self.entries[current][account] = ZERO_HASH; // Remove the current entry from the list

            // Delete the data for the current entry
            delete self.data[current];
        }

        // Reset the sentinel entry for the account
        self.entries[SENTINEL][account] = SENTINEL;
    }

    /**
     * Check if the linked list contains an entry
     *
     * @param self The linked list
     * @param account The account to check if the entry is in the linked list for
     * @param entry The entry to check for
     *
     * @return bool True if the linked list contains the entry
     */
    function contains(
        SentinelList storage self,
        address account,
        bytes32 entry
    ) internal view returns (bool) {
        return SENTINEL != entry && self.entries[entry][account] != ZERO_HASH;
    }

    /**
     * Get all entries in the linked list as an array of bytes32 keys
     *
     * @param self The linked list
     * @param account The account to get the entries for
     * @param start The start entry
     * @param pageSize The page size
     *
     * @return array All entry keys in the linked list
     * @return next The next entry
     */
    function getEntriesPaginated(
        SentinelList storage self,
        address account,
        bytes32 start,
        uint256 pageSize
    ) internal view returns (bytes32[] memory array, bytes32 next) {
        if (start != SENTINEL && !contains(self, account, start)) {
            revert LinkedList_InvalidEntry(start);
        }
        if (pageSize == 0) revert LinkedList_InvalidPage();

        // Init array with max page size
        array = new bytes32[](pageSize);

        // Populate return array
        uint256 entryCount = 0;
        next = self.entries[start][account];
        while (next != ZERO_HASH && next != SENTINEL && entryCount < pageSize) {
            array[entryCount] = next; // Collect the bytes32 key
            next = self.entries[next][account]; // Move to the next entry
            entryCount++;
        }

        // Adjust the size of the returned array
        /// @solidity memory-safe-assembly
        assembly {
            mstore(array, entryCount)
        }
    }
}
