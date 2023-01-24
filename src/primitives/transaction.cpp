// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"
#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

uint256 ComputeTransactionOutputsHash(const std::vector<CTxOut> &vout) {
    CHashWriter ssOutputs(SER_GETHASH, 0);
    for (size_t i = 0; i < vout.size(); i++) {
        CHashWriter ssScript(SER_GETHASH, 0);
        ssScript << CFlatData(vout[i].scriptPubKey);

        CHashWriter ssOut(SER_GETHASH, 0);
        ssOut << vout[i].nValue;
        ssOut << ssScript.GetSHA256();

        CScript script = vout[i].scriptPubKey;
        auto pc = script.end();
        if (script.GetStateIterator(pc)) {
            CScript codescript(script.begin(), pc);
            CScript datascript(pc, script.end());
            CHashWriter ssCodeScript(SER_GETHASH, 0);
            CHashWriter ssDataScript(SER_GETHASH, 0);
            ssCodeScript << CFlatData(codescript);
            ssDataScript << CFlatData(datascript);

            ssOut << ssCodeScript.GetSHA256();
            ssOut << ssDataScript.GetSHA256();
        }
        ssOutputs << ssOut.GetSHA256();
    }
    return ssOutputs.GetSHA256();
}

uint256 ComputeTransactionInputsHash(const std::vector<CTxIn> &vin) {
    CHashWriter ssInputs(SER_GETHASH, 0);
    for (size_t i = 0; i < vin.size(); i++) {
          CHashWriter ssScript(SER_GETHASH, 0);
          ssScript << CFlatData(vin[i].scriptSig);
          CHashWriter ssIn(SER_GETHASH, 0);
          ssIn << vin[i].prevout;
          ssIn << ssScript.GetSHA256();
          ssIn << vin[i].nSequence;
          ssInputs << ssIn.GetSHA256();
    }
    return ssInputs.GetSHA256();
}

template <typename TxType>
CRichTransaction GetRichTransaction(const TxType &tx) {
    CRichTransaction richtx;
    richtx.nVersion = tx.nVersion;
    richtx.nInputCount = tx.vin.size();
    richtx.hashInputs = ComputeTransactionInputsHash(tx.vin);
    richtx.nOutputCount = tx.vout.size();
    richtx.hashOutputs = ComputeTransactionOutputsHash(tx.vout);
    richtx.nLockTime = tx.nLockTime;
    return richtx;
}

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%04d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) {}

static uint256 ComputeCMutableTransactionHash(const CMutableTransaction &tx) {
    if (tx.nVersion == 2) {
      return SerializeHash(GetRichTransaction(tx), SER_GETHASH, 0);
    }
    return SerializeHash(tx, SER_GETHASH, 0);
}

uint256 CMutableTransaction::GetHash() const
{
    return ComputeCMutableTransactionHash(*this);
}

uint256 CTransaction::ComputeHash() const {
    if (this->nVersion == 2) {
      return SerializeHash(GetRichTransaction(*this), SER_GETHASH, 0);
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}
/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime), hash(ComputeHash()) {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = GetTransactionSize(*this);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

int64_t GetTransactionSize(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}
