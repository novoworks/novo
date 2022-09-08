// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>

// The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
// difficulty is cut in half. Doubled if blocks are ahead of schedule.
// One hour
static const uint64_t UNSTEADY_ASERT_HALF_LIFE = 60 * 60;
// Two days.
static const uint64_t STEADY_ASERT_HALF_LIFE = 2 * 24 * 60 * 60;

namespace Consensus {
enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP66 becomes active */
    int32_t BIP66Height;
    /** Block height at which Native Token becomes active */
    int32_t EnableNativeTokenHeight;

    int32_t DisableRichTxIDHeight;
    int32_t SteadyASERTHeight;

    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    uint32_t nCoinbaseMaturity;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nUnsteadyASERTHalfLife;
    int64_t nSteadyASERTHalfLife;
    int64_t nASERTHalfLife;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }

    /** Dogecoin-specific parameters */
    bool fSimplifiedRewards; // Use block height derived rewards rather than previous block hash derived

    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    /** Used by the ASERT DAA activated */
    struct ASERTAnchor {
        int nHeight;
        uint32_t nBits;
        int64_t nPrevBlockTime;
    };

    /** For chains with a checkpoint after the ASERT anchor block, this is always defined */
    ASERTAnchor asertAnchorParams;

};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
