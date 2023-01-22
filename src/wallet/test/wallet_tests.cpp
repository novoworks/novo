// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txmempool.h"
#include "wallet/wallet.h"

#include <set>
#include <stdint.h>
#include <utility>
#include <vector>

#include "rpc/server.h"
#include "test/test_novo.h"
#include "validation.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>
#include <univalue.h>

extern UniValue importmulti(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);

// how many times to run all the tests to have a chance to catch errors that only show up with particular random shuffles
#define RUN_TESTS 100

// some tests fail 1% of the time due to bad luck.
// we repeat those tests this many times and only complain if all iterations of the test fail
#define RANDOM_REPEATS 5

using namespace std;

std::vector<std::unique_ptr<CWalletTx>> wtxn;

typedef set<pair<const CWalletTx*,unsigned int> > CoinSet;

extern CAmount nDustLimit;

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

static const CWallet wallet;
static vector<COutput> vCoins;

static void add_coin(const CAmount& nValue, int nAge = 6*24, bool fIsFromMe = false, int nInput=0)
{
    static int nextLockTime = 0;
    CMutableTransaction tx;
    tx.nLockTime = nextLockTime++;        // so all transactions get different hashes
    tx.vout.resize(nInput+1);
    tx.vout[nInput].nValue = nValue;
    if (fIsFromMe) {
        // IsFromMe() returns (GetDebit() > 0), and GetDebit() is 0 if vin.empty(),
        // so stop vin being empty, and cache a non-zero Debit to fake out IsFromMe()
        tx.vin.resize(1);
    }
    std::unique_ptr<CWalletTx> wtx(new CWalletTx(&wallet, MakeTransactionRef(std::move(tx))));
    if (fIsFromMe)
    {
        wtx->fDebitCached = true;
        wtx->nDebitCached = 1;
    }
    COutput output(wtx.get(), nInput, nAge, true, true);
    vCoins.push_back(output);
    wtxn.emplace_back(std::move(wtx));
}

static void empty_wallet(void)
{
    vCoins.clear();
    wtxn.clear();
}

static bool equal_sets(CoinSet a, CoinSet b)
{
    pair<CoinSet::iterator, CoinSet::iterator> ret = mismatch(a.begin(), a.end(), b.begin());
    return ret.first == a.end() && ret.second == b.end();
}

BOOST_AUTO_TEST_CASE(coin_selection_tests)
{
    CoinSet setCoinsRet, setCoinsRet2;
    CAmount nValueRet;

    LOCK(wallet.cs_wallet);

    // test multiple times to allow for differences in the shuffle order
    for (int i = 0; i < RUN_TESTS; i++)
    {
        empty_wallet();

        // with an empty wallet we can't even pay one coin
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 1 * COIN, 1, 6, 0, vCoins, setCoinsRet, nValueRet));

        add_coin(100*COIN, 4);        // add a new 100 coin output

        // with only a new 1 coin output, we still can't find a mature 10 coin output
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 100 * COIN, 1, 6, 0, vCoins, setCoinsRet, nValueRet));

        // but we can find a new 10 coin output
        BOOST_CHECK( wallet.SelectCoinsMinConf( 100 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 100 * COIN);

        add_coin(200*COIN);           // add a mature 200 coin output

        // we can't make 300 coins of mature outputs
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 300 * COIN, 1, 6, 0, vCoins, setCoinsRet, nValueRet));

        // we can make 300 coin of new outputs
        BOOST_CHECK( wallet.SelectCoinsMinConf( 300 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 300 * COIN);

        add_coin(500*COIN);           // add a mature 50 coin output,
        add_coin(1000*COIN, 3, true); // a new 100 coin output sent from one of our own addresses
        add_coin(2000*COIN);          // and a mature 200 coin output

        // now we have new: 10+100=110 (of which 100 was self-sent), and mature: 20+50+200=270.  total = 380

        // we can't make 3800 coins only if we disallow new output:
        BOOST_CHECK(!wallet.SelectCoinsMinConf(3800 * COIN, 1, 6, 0, vCoins, setCoinsRet, nValueRet));
        // we can't even make 370 coins if we don't allow new output even if they're from us
        BOOST_CHECK(!wallet.SelectCoinsMinConf(3800 * COIN, 6, 6, 0, vCoins, setCoinsRet, nValueRet));
        // but we can make 370 coins if we accept new output from ourself
        BOOST_CHECK( wallet.SelectCoinsMinConf(3700 * COIN, 1, 6, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 3700 * COIN);
        // and we can make 380 coins if we accept all new output
        BOOST_CHECK( wallet.SelectCoinsMinConf(3800 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 3800 * COIN);

        // try making 3400 coins from 100,200,500,1000,2000 - we can't do it exactly
        BOOST_CHECK( wallet.SelectCoinsMinConf(3400 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 3500 * COIN);       // but 3500 coins is closest
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);     // the best should be 2000+1000+500.  it's incredibly unlikely the 100 or 200 got included (but possible)

        // when we try making 700 coins, the smaller outputs (100,200,500) are enough.  We should see just 200+500
        BOOST_CHECK( wallet.SelectCoinsMinConf( 700 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 700 * COIN);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);

        // when we try making 800 coins, the smaller outputs (100,200,500) are exactly enough.
        BOOST_CHECK( wallet.SelectCoinsMinConf( 800 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK(nValueRet == 800 * COIN);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);

        // when we try making 900 coins, no subset of smaller outputs is enough, and we get the next bigger output (1000)
        BOOST_CHECK( wallet.SelectCoinsMinConf( 900 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1000 * COIN);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        // now clear out the wallet and start again to test choosing between subsets of smaller coins and the next biggest coin
        empty_wallet();

        add_coin( 600*COIN);
        add_coin( 700*COIN);
        add_coin( 800*COIN);
        add_coin(2000*COIN);
        add_coin(3000*COIN);
        // now we have 600+700+800+2000+3000 = 7100 coins total

        // check that we have 7100 and not 7110
        BOOST_CHECK( wallet.SelectCoinsMinConf(7100 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK(!wallet.SelectCoinsMinConf(7110 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));

        // now try making 1600 coins.  the best smaller outputs can do is 600+700+800 = 2100; not as good at the next biggest output, 2000
        BOOST_CHECK( wallet.SelectCoinsMinConf(1600 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 2000 * COIN); // we should get 200 in one output
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        add_coin( 500*COIN);
        // now we have 500+600+700+800+2000+3000 = 7600 coins total

        // now if we try making 1600 coins again, the smaller outputs can make 500+600+700 = 1800 coins, better than the next biggest output, 2000
        BOOST_CHECK( wallet.SelectCoinsMinConf(1600 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1800 * COIN); // we should get 180 in 3 outputs
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);

        add_coin( 1800*COIN);
        // now we have 500+600+700+800+1800+2000+3000 = 9400 coins total

        // and now if we try making 1600 coins again, the smaller outputs can make 500+600+700 = 1800 coins, the same as the next biggest output, 1800
        BOOST_CHECK( wallet.SelectCoinsMinConf(1600 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1800 * COIN);  // we should get 1800 in 1 output
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U); // because in the event of a tie, the biggest output wins

        // now try making 1100 coins.  we should get 500+600
        BOOST_CHECK( wallet.SelectCoinsMinConf(1100 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1100 * COIN);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);

        // check that the smallest bigger output is used
        add_coin( 10000*COIN);
        add_coin( 20000*COIN);
        add_coin( 30000*COIN);
        add_coin( 40000*COIN);
        // now we have 500+600+700+800+1800+2000+3000+10000+20000+30000+40000 = 109400 coins

        BOOST_CHECK( wallet.SelectCoinsMinConf(9500 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 10000 * COIN);  // we should get 10000 coins in 1 output
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        BOOST_CHECK( wallet.SelectCoinsMinConf(19500 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 20000 * COIN);  // we should get 20000 coins in 1 output
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        // empty the wallet and start again, now with fractions of a coin, to test small change avoidance

        empty_wallet();
        add_coin(CWallet::GetMinChange() * 1 / 16);
        add_coin(CWallet::GetMinChange() * 2 / 16);
        add_coin(CWallet::GetMinChange() * 3 / 16);
        add_coin(CWallet::GetMinChange() * 4 / 16);
        add_coin(CWallet::GetMinChange() * 5 / 16);
        add_coin(CWallet::GetMinChange() * 6 / 16);

        // try making 1 * GetMinChange() from the 1.5 * GetMinChange()
        // we'll get change smaller than GetMinChange() whatever happens, so can expect GetMinChange() exactly
        BOOST_CHECK( wallet.SelectCoinsMinConf(CWallet::GetMinChange(), 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, CWallet::GetMinChange());

        // but if we add a bigger output, small change is avoided
        add_coin(1111*CWallet::GetMinChange());

        // try making 1 from 0.1 + 0.2 + 0.3 + 0.4 + 0.5 + 1111 = 1112.5
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * CWallet::GetMinChange(), 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * CWallet::GetMinChange()); // we should get the exact amount

        // if we add more small output:
        add_coin(CWallet::GetMinChange() * 7 / 16);
        add_coin(CWallet::GetMinChange() * 8 / 16);

        // and try again to make 1.0 * GetMinChange()
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * CWallet::GetMinChange(), 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * CWallet::GetMinChange()); // we should get the exact amount

        // run the 'mtgox' test (see http://blockexplorer.com/tx/29a3efd3ef04f9153d47a990bd7b048a4b2d213daaa5fb8ed670fb85f13bdbcf)
        // they tried to consolidate 10 50k outputs into one 500k output, and ended up with 50k in change
        empty_wallet();
        for (int j = 0; j < 20; j++)
            add_coin(50000 * COIN);

        BOOST_CHECK( wallet.SelectCoinsMinConf(500000 * COIN, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 500000 * COIN); // we should get the exact amount
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 10U); // in ten outputs

        // if there's not enough in the smaller coins to make at least 1 * GetMinChange() change (0.5+0.6+0.7 < 1.0+1.0),
        // we need to try finding an exact subset anyway

        // sometimes it will fail, and so we use the next biggest output:
        empty_wallet();
        add_coin(CWallet::GetMinChange() * 5 / 16);
        add_coin(CWallet::GetMinChange() * 6 / 16);
        add_coin(CWallet::GetMinChange() * 7 / 16);
        add_coin(1111 * CWallet::GetMinChange());
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * CWallet::GetMinChange(), 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1111 * CWallet::GetMinChange()); // we get the bigger output
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);

        // but sometimes it's possible, and we use an exact subset (0.4 + 0.6 = 1.0)
        empty_wallet();
        add_coin(CWallet::GetMinChange() * 6 / 16);
        add_coin(CWallet::GetMinChange() * 8 / 16);
        add_coin(CWallet::GetMinChange() * 10 / 16);
        add_coin(1111 * CWallet::GetMinChange());
        BOOST_CHECK( wallet.SelectCoinsMinConf(CWallet::GetMinChange(), 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, CWallet::GetMinChange());   // we should get the exact amount
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U); // in two outputs 0.4+0.6

        // test avoiding small change
        empty_wallet();
        add_coin(CWallet::GetMinChange() * 2 / 16);
        add_coin(CWallet::GetMinChange() * 1);
        add_coin(CWallet::GetMinChange() * 100);

        // trying to make 100.01 from these three outputs
        BOOST_CHECK(wallet.SelectCoinsMinConf(CWallet::GetMinChange() * 1601 / 16, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, CWallet::GetMinChange() * 1618 / 16); // we should get all outputs
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);

        // but if we try to make 99.9, we should take the bigger of the two small outputs to avoid small change
        BOOST_CHECK(wallet.SelectCoinsMinConf(CWallet::GetMinChange() * 1599 / 16, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 101 * CWallet::GetMinChange());
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);

        // test with many inputs
        for (CAmount amt=15*CENT; amt < 10000 * COIN; amt*=10) {
             empty_wallet();
             // Create 676 inputs (=  (old MAX_STANDARD_TX_SIZE == 100000)  / 148 bytes per input)
             for (uint16_t j = 0; j < 676; j++)
                 add_coin(amt);
             BOOST_CHECK(wallet.SelectCoinsMinConf(20*CENT, 1, 1, 0, vCoins, setCoinsRet, nValueRet));
             if (amt - 20*CENT < CWallet::GetMinChange()) {
                 // needs more than one input:
                 uint16_t returnSize = std::ceil((20.0 * CENT + CWallet::GetMinChange())/amt);
                 CAmount returnValue = amt * returnSize;
                 BOOST_CHECK_EQUAL(nValueRet, returnValue);
                 BOOST_CHECK_EQUAL(setCoinsRet.size(), returnSize);
             } else {
                 // one input is sufficient:
                 BOOST_CHECK_EQUAL(nValueRet, amt);
                 BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);
             }
        }

        // test randomness
        {
            empty_wallet();
            for (int i2 = 0; i2 < 100; i2++)
                add_coin(COIN);

            // picking 50 from 100 outputs doesn't depend on the shuffle,
            // but does depend on randomness in the stochastic approximation code
            BOOST_CHECK(wallet.SelectCoinsMinConf(50 * COIN, 1, 6, 0, vCoins, setCoinsRet , nValueRet));
            BOOST_CHECK(wallet.SelectCoinsMinConf(50 * COIN, 1, 6, 0, vCoins, setCoinsRet2, nValueRet));
            BOOST_CHECK(!equal_sets(setCoinsRet, setCoinsRet2));

            int fails = 0;
            for (int j = 0; j < RANDOM_REPEATS; j++)
            {
                // selecting 1 from 100 identical outputs depends on the shuffle; this test will fail 1% of the time
                // run the test RANDOM_REPEATS times and only complain if all of them fail
                BOOST_CHECK(wallet.SelectCoinsMinConf(COIN, 1, 6, 0, vCoins, setCoinsRet , nValueRet));
                BOOST_CHECK(wallet.SelectCoinsMinConf(COIN, 1, 6, 0, vCoins, setCoinsRet2, nValueRet));
                if (equal_sets(setCoinsRet, setCoinsRet2))
                    fails++;
            }
            BOOST_CHECK_NE(fails, RANDOM_REPEATS);

            // add 75 coins in small change.  not enough to make 90 coins,
            // then try making 90 coins.  there are multiple competing "smallest bigger" outputs,
            // one of which should be picked at random
            add_coin(5 * COIN);
            add_coin(10 * COIN);
            add_coin(15 * COIN);
            add_coin(20 * COIN);
            add_coin(25 * COIN);

            fails = 0;
            for (int j = 0; j < RANDOM_REPEATS; j++)
            {
                // selecting 1 from 100 identical outputs depends on the shuffle; this test will fail 1% of the time
                // run the test RANDOM_REPEATS times and only complain if all of them fail
                BOOST_CHECK(wallet.SelectCoinsMinConf(90*COIN, 1, 6, 0, vCoins, setCoinsRet , nValueRet));
                BOOST_CHECK(wallet.SelectCoinsMinConf(90*COIN, 1, 6, 0, vCoins, setCoinsRet2, nValueRet));
                if (equal_sets(setCoinsRet, setCoinsRet2))
                    fails++;
            }
            BOOST_CHECK_NE(fails, RANDOM_REPEATS);
        }
    }
    empty_wallet();
}

BOOST_AUTO_TEST_CASE(ApproximateBestSubset)
{
    CoinSet setCoinsRet;
    CAmount nValueRet;

    LOCK(wallet.cs_wallet);

    empty_wallet();

    // Test vValue sort order
    for (int i = 0; i < 1000; i++)
        add_coin(1000 * COIN);
    add_coin(3 * COIN);

    BOOST_CHECK(wallet.SelectCoinsMinConf(1003 * COIN, 1, 6, 0, vCoins, setCoinsRet, nValueRet));
    BOOST_CHECK_EQUAL(nValueRet, 1003 * COIN);
    BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);

    empty_wallet();
}

BOOST_FIXTURE_TEST_CASE(rescan, TestChain240Setup)
{
    LOCK(cs_main);

    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = chainActive.Tip();
    GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = chainActive.Tip();

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet;
        LOCK(wallet.cs_wallet);
        wallet.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
        BOOST_CHECK_EQUAL(oldTip, wallet.ScanForWalletTransactions(oldTip));
        BOOST_CHECK(wallet.GetImmatureBalance() < (240000000 * COIN));
    }

    // Prune the older block file.
    PruneOneBlockFile(oldTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({oldTip->GetBlockPos().nFile});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet;
        LOCK(wallet.cs_wallet);
        wallet.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
        BOOST_CHECK_EQUAL(newTip, wallet.ScanForWalletTransactions(oldTip));
        BOOST_CHECK(wallet.GetImmatureBalance() < (120000000 * COIN));
    }

    // Verify importmulti RPC returns failure for a key whose creation time is
    // before the missing block, and success for a key whose creation time is
    // after.
    {
        CWallet wallet;
        CWallet *backup = ::pwalletMain;
        ::pwalletMain = &wallet;
        UniValue keys;
        keys.setArray();
        UniValue key;
        key.setObject();
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())));
        key.pushKV("timestamp", 0);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        key.clear();
        key.setObject();
        CKey futureKey;
        futureKey.MakeNewKey(true);
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(futureKey.GetPubKey())));
        key.pushKV("timestamp", newTip->GetBlockTimeMax() + 7200);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back(keys);

        UniValue response = importmulti(request);
        BOOST_CHECK_EQUAL(response.write(), strprintf("[{\"success\":false,\"error\":{\"code\":-1,\"message\":\"Failed to rescan before time %d, transactions may be missing.\"}},{\"success\":true}]", newTip->GetBlockTimeMax()));
        ::pwalletMain = backup;
    }
}

// Verify importwallet RPC starts rescan at earliest block with timestamp
// greater or equal than key birthday. Previously there was a bug where
// importwallet RPC would start the scan at the latest block with timestamp less
// than or equal to key birthday.
BOOST_FIXTURE_TEST_CASE(importwallet_rescan, TestChain240Setup)
{
    CWallet *pwalletMainBackup = ::pwalletMain;
    LOCK(cs_main);

    // Create two blocks with same timestamp to verify that importwallet rescan
    // will pick up both blocks, not just the first.
    const int64_t BLOCK_TIME = chainActive.Tip()->GetBlockTimeMax() + 5;
    SetMockTime(BLOCK_TIME);
    coinbaseTxns.emplace_back(*CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    coinbaseTxns.emplace_back(*CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    // Set key birthday to block time increased by the timestamp window, so
    // rescan will start at the block time.
    const int64_t KEY_TIME = BLOCK_TIME + 7200;
    SetMockTime(KEY_TIME);
    coinbaseTxns.emplace_back(*CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    // Import key into wallet and call dumpwallet to create backup file.
    {
        CWallet wallet;
        LOCK(wallet.cs_wallet);
        wallet.mapKeyMetadata[coinbaseKey.GetPubKey().GetID()].nCreateTime = KEY_TIME;
        wallet.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back("wallet.backup");
        ::pwalletMain = &wallet;
        ::dumpwallet(request);
    }

    // Call importwallet RPC and verify all blocks with timestamps >= BLOCK_TIME
    // were scanned, and no prior blocks were scanned.
    {
        CWallet wallet;

        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back("wallet.backup");
        ::pwalletMain = &wallet;
        ::importwallet(request);

        BOOST_CHECK_EQUAL(wallet.mapWallet.size(), 3);
        BOOST_CHECK_EQUAL(coinbaseTxns.size(), 243);
        for (size_t i = 0; i < coinbaseTxns.size(); ++i) {
            bool found = wallet.GetWalletTx(coinbaseTxns[i].GetHash());
            bool expected = i >= 240;
            BOOST_CHECK_EQUAL(found, expected);
        }
    }

    SetMockTime(0);
    ::pwalletMain = pwalletMainBackup;
}

BOOST_AUTO_TEST_CASE(GetMinimumFee_test)
{
    uint64_t value = 2000000 * COIN;

    CMutableTransaction tx;
    CTxMemPool pool(payTxFee);
    CTxOut txout1(value, (CScript)vector<unsigned char>(24, 0));
    tx.vout.push_back(txout1);

    int64_t nMinTxFee = 25 * 10000;

    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 250, 0, pool), nMinTxFee * 0.25);
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 1000, 0, pool), nMinTxFee * 1.0);
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 1999, 0, pool), nMinTxFee * 1.999);
}

BOOST_AUTO_TEST_CASE(GetMinimumFee_dust_test)
{
    // Derived from main net TX 3d6ec3ae2aca3ae0a6c65074fd8ee888cd7ed262f2cbaa25d33861989324a14e
    CMutableTransaction tx;
    CTxMemPool pool(payTxFee);
    CTxOut txout1(139496846, (CScript)vector<unsigned char>(24, 0)); // Regular output
    CTxOut txout2(49999, (CScript)vector<unsigned char>(24, 0)); // Dust output
    tx.vout.push_back(txout1);
    tx.vout.push_back(txout2);

    CAmount nMinTxFee = 25 * 10000;

    // Confirm dust penalty fees are added on
    // Because this is ran by the wallet, this takes the discardThreshold,
    // not the dust limit
    CAmount nDustPenalty = 50000;

    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 963, 0, pool), nDustPenalty + (nMinTxFee * 0.963));
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 1000, 0, pool), nDustPenalty + (nMinTxFee * 1.000));
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 1999, 0, pool), nDustPenalty + (nMinTxFee * 1.999));

    // change the discard threshold

    CWallet::discardThreshold = COIN / 1000;

    // Confirm dust penalty fees are not added

    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 963, 0, pool), nMinTxFee * 0.963);
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 1000, 0, pool), nMinTxFee * 1.000);
    BOOST_CHECK_EQUAL(CWallet::GetMinimumFee(tx, 1999, 0, pool), nMinTxFee * 1.999);

    CWallet::discardThreshold = COIN;
}

BOOST_AUTO_TEST_SUITE_END()
