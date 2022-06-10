// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include "core_io.h"
#include "chainparamsseeds.h"

#include <cassert>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 0x11de784a
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000,
 * hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d7fffff, nNonce=2083236893,
 * vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase
 * 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=2000000.0000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount genesisReward) {
    const char *pszTimestamp =
        "The Times 02/Dec/2021 Fourth jab to fight variants";
    const CScript genesisOutputScript =
      CScript() << OP_DUP
                << OP_HASH160
                << ParseHex("0567b5f0544536d023fbb123b830f626d9c80389")
                << OP_EQUALVERIFY
                << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.nSubsidyHalvingInterval = 210000;
        // BIP34 is never enforced in Novo v2 blocks, so we enforce from v3
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("00000000df5c5164b4516916ac7a520df6039e8cac3d4ac9235e15eace81acd2");
        consensus.BIP66Height = 1;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 150;
        consensus.nCoinbaseMaturity = 100;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 9576; // 95% of 10,080
        consensus.nMinerConfirmationWindow = 10080; // 60 * 24 * 7 = 10,080 blocks, or one week
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        consensus.nUnsteadyASERTHalfLife = UNSTEADY_ASERT_HALF_LIFE;
        consensus.nSteadyASERTHalfLife = STEADY_ASERT_HALF_LIFE;
        consensus.SteadyASERTHeight = 0;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000d9e4a0215757");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("00000000be8113904edd472404e861e0492f980af7e5345fdd87ce0e41b072ba");

        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
          1,            // anchor block height
          0x1d00ffff,   // anchor block nBits
          1638457291,   // anchor block previous block timestamp
        };

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xe0;
        pchMessageStart[1] = 0xfe;
        pchMessageStart[2] = 0xfe;
        pchMessageStart[3] = 0xca;
        vAlertPubKey = ParseHex("04d4da7a5dae4db797d9b0644d57a5cd50e05a70f36091cd62e2fc41c98ded06340be5a43a35e185690cd9cde5d72da8f6d065b499b06f51dcfba14aad859f443a");
        nDefaultPort = 8666;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1638457291, 0x7823b7d4, 0x1d00ffff, 1, 2000000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0000000000b3de1ef5bd7c20708dbafc3df0441877fa4a59cda22b4c2d4f39ce"));
        assert(genesis.hashMerkleRoot == uint256S("cbdb156beade97595e5d6ff8b0ee609033030bec41851576e30c4f5a68e2cbeb"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("novobitcoin.org", "seed.novobitcoin.org", true));
        vSeeds.push_back(CDNSSeedData("novoscan.org", "seed.novoscan.org", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = { {
                {0, uint256S("0000000000b3de1ef5bd7c20708dbafc3df0441877fa4a59cda22b4c2d4f39ce")},
                {11111, uint256S("00000000e5ab5f4cc6ae918f997fe188d906690957e1f6a30c3e28c4cf4e561f")},
                {33333, uint256S("00000000335152fea863a7e2b6320ec12e5b9d6b0bba9c4f6a9970ab6c1aa1e2")},
                {55555, uint256S("00000000224682e5cb41eb91b04c3a872f11e3216ef354a79b48aa2c4e6717aa")},
                {66666, uint256S("0000000000a56eaa524bd157ef8649e5427af2c36e902dc96a4025de25f0f110")},
                {77777, uint256S("000000000082cb226a8253dfde5c1cdd6f7dac63802aa1d5f83d16a865cdfac3")},
                {88888, uint256S("000000000019b95eaf590aa5818a2d130a2b2f65b63215f4c29afad912e66c00")},
                {93000, uint256S("00000000000c181a2deb48daa68ed7d2f93fc76f58ca3299928a3223c52f002e")},
                {100000, uint256S("000000000001045fb2376eda493fdb994d34c050741d88cdd8ec282becc2ba61")},
            }};

        chainTxData = ChainTxData{
            // Data as of block e4b4ecda4c022406c502a247c0525480268ce7abbbef632796e8ca1646425e75 (height 3854173).
            // Tx estimate based on average of year 2021 (~40k transactions per day)
            1642953295, // * UNIX timestamp of last checkpoint block
            29980,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            3        // * estimated number of transactions per second after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";

        consensus.nCoinbaseMaturity = 100;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("");
        consensus.BIP66Height = 1;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 150;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 2880; // 2 days (note this is significantly lower than Bitcoin standard)
        consensus.nMinerConfirmationWindow = 10080; // 60 * 24 * 7 = 10,080 blocks, or one week
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        consensus.nUnsteadyASERTHalfLife = UNSTEADY_ASERT_HALF_LIFE;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        pchMessageStart[0] = 0x3b;
        pchMessageStart[1] = 0xfa;
        pchMessageStart[2] = 0xab;
        pchMessageStart[3] = 0xce;
        vAlertPubKey = ParseHex("042756726da3c7ef515d89212ee1705023d14be389e25fe15611585661b9a20021908b2b80a3c7200a0139dd2b26946606aab0eef9aa7689a6dc2c7eee237fa834");
        nDefaultPort = 18666;

        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
          1,            // anchor block height
          0x1d00ffff,   // anchor block nBits
          1638457834,   // anchor block previous block timestamp
        };

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1638457834, 0xaadc772a, 0x1d00ffff, 1, 2000000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0000000000867f82407320d0939e3e618e5579156a4c0f21c067ea31edd39f49"));
        assert(genesis.hashMerkleRoot == uint256S("cbdb156beade97595e5d6ff8b0ee609033030bec41851576e30c4f5a68e2cbeb"));

        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("testnet.novobitcoin.org", "testnet-seed.novobitcoin.org", true));
        vSeeds.push_back(CDNSSeedData("testnet.novoscan.org", "testnet-seed.novoscan.org", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {{
        }};

        chainTxData = ChainTxData{
            // Data as of block 07fef07a255d510297c9189dc96da5f4e41a8184bc979df8294487f07fee1cf3 (height 3286675)
            1635884142, // * UNIX timestamp of last checkpoint block
            4780345,    // * total number of transactions between genesis and last checkpoint
            0.02        // * estimated number of transactions per second after that timestamp
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP66Height = 1;
        consensus.powLimit = uint256S("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 150;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 540; // 75% for testchains
        consensus.nMinerConfirmationWindow = 720; // Faster than normal for regtest (2,520 instead of 10,080)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xe2;
        pchMessageStart[1] = 0xfe;
        pchMessageStart[2] = 0xfe;
        pchMessageStart[3] = 0xca;
        nDefaultPort = 18999;

        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
          1,            // anchor block height
          0x1d00ffff,   // anchor block nBits
          1638386056,   // anchor block previous block timestamp
        };

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1638457291, 2, 0x207fffff, 1, 2000000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0693faff1ff2efb098f89871433dcc9d631929a8616fc55415268d6339f909d5"));
        assert(genesis.hashMerkleRoot == uint256S("cbdb156beade97595e5d6ff8b0ee609033030bec41851576e30c4f5a68e2cbeb"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {{
            { 0, uint256S("0693faff1ff2efb098f89871433dcc9d631929a8616fc55415268d6339f909d5")},
        }};

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);  // 0x6f
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);  // 0xc4
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);  // 0xef
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
