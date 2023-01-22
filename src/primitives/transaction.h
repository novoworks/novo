// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NOVO_PRIMITIVES_TRANSACTION_H
#define NOVO_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"

static const int SERIALIZE_TRANSACTION = 0x00;

/** An amount smaller than this is considered dust */
extern CAmount nDustLimit;

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    uint32_t n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, uint32_t nIn) { hash = hashIn; n = nIn; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
        READWRITE(n);
    }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        int cmp = a.hash.Compare(b.hash);
        return cmp < 0 || (cmp == 0 && a.n < b.n);
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    std::string ToFullString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(prevout);
        READWRITE(*(CScriptBase*)(&scriptSig));
        READWRITE(nSequence);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    static const uint64_t CONTRACT_FLAG = 0x8000000000000000;
    static const uint64_t CONTRACT_FT = CONTRACT_FLAG | 0;
    static const uint64_t CONTRACT_NFT = CONTRACT_FLAG | 1;
    static const uint64_t CONTRACT_FT_MINT = CONTRACT_FLAG | 2;
    static const uint64_t CONTRACT_NFT_MINT = CONTRACT_FLAG | 3;

    static const uint64_t MAX_CONTRACT_TYPE = CONTRACT_FLAG | 3;
    static const uint64_t MAX_CONTRACT_METADATA_SIZE = 1024;

    uint64_t contractType;
    COutPoint contractID;
    uint256 contractValue;
    uint256 contractMaxSupply;
    std::string contractMetadata;

    CAmount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);
    CTxOut(uint64_t contractTypeIn, COutPoint contractIDIn, uint256 contractValueIn, uint256 contractMaxSupplyIn, std::string contractMetadataIn, const CAmount& nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (!ser_action.ForRead()) {
            if (IsContract()) {
                READWRITE(contractType);
                READWRITE(contractID);
                READWRITE(contractValue);
                READWRITE(contractMaxSupply);
                READWRITE(contractMetadata);
            }
            READWRITE(nValue);
        } else {
            SetNull();

            uint64_t nType = 0;
            READWRITE(nType);
            if (nType & CONTRACT_FLAG && nType <= MAX_CONTRACT_TYPE) {
                contractType = nType;

                READWRITE(contractID);
                READWRITE(contractValue);
                READWRITE(contractMaxSupply);
                READWRITE(contractMetadata);
                READWRITE(nValue);
            } else {
                nValue = nType;
            }
        }
        READWRITE(*(CScriptBase*)(&scriptPubKey));
    }

    void SetNull()
    {
        contractType = 0;
        contractID.SetNull();
        contractValue.SetNull();
        contractMaxSupply.SetNull();
        contractMetadata.clear();
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    // Novo: allow comparison against different dustlimit parameters
    bool IsDust(const CAmount dustLimit) const
    {
      if (scriptPubKey.IsUnspendable())
          return false;

      return (nValue < dustLimit);
    }

    bool IsContract() const
    {
        return (contractType & CONTRACT_FLAG && contractType <= MAX_CONTRACT_TYPE);
    }

    static const char* ContractTypeString(const uint64_t nType) {
        switch (nType) {
        case CONTRACT_FT:
            return "FT";
        case CONTRACT_NFT:
            return "NFT";
        case CONTRACT_FT_MINT:
            return "FT_MINT";
        case CONTRACT_NFT_MINT:
            return "NFT_MINT";
        default: break;
        }
        return "Unknown";
    }

    static const uint64_t GetContractTypeByName(const std::string sTypeName) {
        if (sTypeName == "FT") {
            return CONTRACT_FT;
        } else if (sTypeName == "NFT") {
            return CONTRACT_NFT;
        } else if (sTypeName == "FT_MINT") {
            return CONTRACT_FT_MINT;
        } else if (sTypeName == "NFT_MINT") {
            return CONTRACT_NFT_MINT;
        }
        return 0;
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.contractType  == b.contractType &&
                a.contractID    == b.contractID &&
                a.contractValue == b.contractValue &&
                a.contractMaxSupply == b.contractMaxSupply &&
                a.contractMetadata  == b.contractMetadata &&
                a.nValue        == b.nValue &&
                a.scriptPubKey  == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
inline void UnserializeTransaction(TxType& tx, Stream& s) {

    s >> tx.nVersion;
    tx.vin.clear();
    tx.vout.clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    /* We read a non-empty vin. Assume a normal vout follows. */
    s >> tx.vout;
    s >> tx.nLockTime;
}

template<typename Stream, typename TxType>
inline void SerializeTransaction(const TxType& tx, Stream& s) {
    s << tx.nVersion;
    s << tx.vin;
    s << tx.vout;
    s << tx.nLockTime;
}

/**
 * RichTX, holds every piece of key information of a transaction for advanced scripting
 */
class CRichTransaction {
public:
    int32_t nVersion;
    uint32_t nInputCount;
    uint256 hashInputs;
    uint32_t nOutputCount;
    uint256 hashOutputs;
    uint32_t nLockTime;

    CRichTransaction() { SetNull(); }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(nInputCount);
        READWRITE(hashInputs);
        READWRITE(nOutputCount);
        READWRITE(hashOutputs);
        READWRITE(nLockTime);
    }

    void SetNull() {
        nVersion = 0;
        nInputCount = 0;
        hashInputs.SetNull();
        nOutputCount = 0;
        hashOutputs.SetNull();
        nLockTime = 0;
    }
};

/**
 * The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = 1;

    // Changing the default transaction version requires a two step process:
    // first adapting relay policy by bumping MAX_STANDARD_VERSION, and then
    // later date bumping the default CURRENT_VERSION at which point both
    // CURRENT_VERSION and MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION = 2;

    static const int32_t RICHTX_VERSION = 2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const int32_t nVersion;
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t nLockTime;

private:
    /** Memory only. */
    const uint256 hash;

    uint256 ComputeHash() const;

public:
    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }

    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const {
        return hash;
    }


    // Return sum of txouts.
    CAmount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;

    /**
     * Get the total transaction size in bytes.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    std::string ToString() const;

};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;

    friend bool operator==(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return a.GetHash() == b.GetHash();
    }
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
static inline CTransactionRef MakeTransactionRef() { return std::make_shared<const CTransaction>(); }
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }

/** Compute the size of a transaction */
int64_t GetTransactionSize(const CTransaction &tx);

#endif // NOVO_PRIMITIVES_TRANSACTION_H
