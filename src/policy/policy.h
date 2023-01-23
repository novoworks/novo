// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NOVO_POLICY_POLICY_H
#define NOVO_POLICY_POLICY_H

#include "consensus/consensus.h"
#include "script/interpreter.h"
#include "script/standard.h"
#include "amount.h"

#include <string>

class CCoinsViewCache;

/** Recommended transaction fee per kilobyte by Novo developers
  *
  * All fee defaults used throughout the client derive their
  * value from this base default.
  */
static const CAmount RECOMMENDED_MIN_TX_FEE = 25 * COIN;

/** Default for -blockmaxsize, which controls the maximum size of block the mining code will create **/
static const unsigned int DEFAULT_BLOCK_MAX_SIZE = 1500 * 1000; // 1.5mb
/** Default for -blockprioritysize, maximum space for zero/low-fee transactions **/
static const unsigned int DEFAULT_BLOCK_PRIORITY_SIZE = 0;
/** Default for -blockmintxfee, which sets the minimum feerate for a transaction in blocks created by mining code **/
static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE = 25 * 10000;
/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 1250 * 1000; // 1.25mb
/** The minimum size for transactions we're willing to relay/mine */
static const unsigned int MIN_STANDARD_TX_SIZE = 65;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const unsigned int MAX_STANDARD_TX_SIGOPS_COUNT = MAX_TX_SIGOPS_COUNT/5;
/** Default for -maxmempool, maximum megabytes of mempool memory usage */
static const unsigned int DEFAULT_MAX_MEMPOOL_SIZE = 1000;
/** Default for -incrementalrelayfee, which sets the minimum feerate increase
 *  for mempool limiting or BIP 125 replacement
 *
 *  Novo:    Increment mempool limits and accept RBF in steps of 0.01 NOVO
 *  Calculation: DEFAULT_MIN_RELAY_TX_FEE = RECOMMENDED_MIN_TX_FEE / 10
 *               DEFAULT_INCREMENTAL_RELAY_FEE = DEFAULT_MIN_RELAY_TX_FEE / 10
 *
 *  Rationale:   This implements a smaller granularity than the wallet
 *               implementation for fee increments by default, leaving room for
 *               alternative increment strategies, yet limiting the amount of
 *               ineffective RBF spam we expose the network to. This also makes
 *               an RBF fee bump 10x cheaper than a CPFP transaction, because
 *               RBF leaves no on-chain waste, whereas CPFP adds another
 *               transaction to the chain.
 */
static const CAmount DEFAULT_INCREMENTAL_RELAY_FEE = CENT;
/** Default for -bytespersigop */
static const unsigned int DEFAULT_BYTES_PER_SIGOP = 20;

/**
 * Novo: Default dust limit that is evaluated when considering whether a
 * transaction output is required to pay additional fee for relay and inclusion
 * in blocks. Overridden by -dustlimit
 */
static const CAmount DEFAULT_DUST_LIMIT = 5 * COIN;
/**
 * Novo: Default hard dust limit that is evaluated when considering whether
 * a transaction is standard. Transactions under this limit will not be accepted
 * to the mempool and thus not relayed. Can be overridden by -harddustlimit
 *
 * Changing the hard dust limit changes which transactions are standard and
 * should be done with care and ideally rarely. It makes sense to only increase
 * this limit after prior releases were already not creating outputs below the
 * new threshold
 */
static const CAmount DEFAULT_HARD_DUST_LIMIT = 5 * COIN;

/**
 * Standard script verification flags that standard transactions will comply
 * with. However scripts violating these flags may still be present in valid
 * blocks and we must accept those blocks.
 */
static const unsigned int STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                         SCRIPT_VERIFY_DERSIG |
                                                         SCRIPT_VERIFY_MINIMALDATA |
                                                         SCRIPT_VERIFY_NULLDUMMY |
                                                         SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                         SCRIPT_VERIFY_CLEANSTACK |
                                                         SCRIPT_VERIFY_MINIMALIF;

/** For convenience, standard but not mandatory verify flags. */
static const unsigned int STANDARD_NOT_MANDATORY_VERIFY_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS;

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType);
    /**
     * Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
bool IsStandardTx(const CTransaction& tx, std::string& reason);
    /**
     * Check for standard transaction types
     * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
     * @return True if all inputs (scriptSigs) use only standard transaction forms
     */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);

extern CFeeRate incrementalRelayFee;
extern CFeeRate dustRelayFee;
extern unsigned int nBytesPerSigOp;
extern CAmount nDustLimit;
extern CAmount nHardDustLimit;


#endif // NOVO_POLICY_POLICY_H
