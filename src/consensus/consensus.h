// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdint.h>

/** The maximum allowed size for a block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_BASE_SIZE = 8 * 1000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COUNT = 8 * 75000;

/** The maximum allowed number of signature check operations in a transaction (network rule) */
static const int64_t MAX_TX_SIGOPS_COUNT = 75000/5;

/** The maximum allowed size for a transaction, in bytes (network rule) */
static const unsigned int MAX_TX_BASE_SIZE = 8 * 1000000;
/** The minimum allowed size for a transaction, in bytes (network rule) */
static const unsigned int MIN_TX_BASE_SIZE = 65;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
