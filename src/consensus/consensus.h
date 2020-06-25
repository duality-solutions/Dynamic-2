// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DYNAMIC_CONSENSUS_CONSENSUS_H
#define DYNAMIC_CONSENSUS_CONSENSUS_H

/** The maximum allowed size for a transaction, in bytes */
static const unsigned int MAX_TX_SIZE = 1000000; // 1 MB to match the default maximum network send size.
/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 4194304; //4MB
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS_COST = MAX_BLOCK_SIZE / 50;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 10;

/** ASSET START */
#define UNUSED_VAR     __attribute__ ((unused))
//! This variable needs to in this class because undo.h uses it. However because it is in this class
//! it causes unused variable warnings when compiling. This UNUSED_VAR removes the unused warnings
UNUSED_VAR static bool fAssetsIsActive = false;
UNUSED_VAR static bool fMsgRestAssetIsActive = false;
UNUSED_VAR static bool fTransferScriptIsActive = false;

unsigned int GetMaxBlockSerializedSize();
/** ASSET END */

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // DYNAMIC_CONSENSUS_CONSENSUS_H
