// Copyright (c) 2021 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NOVO_NOVO_FEES_H
#define NOVO_NOVO_FEES_H

#include "amount.h"
#include "chain.h"
#include "chainparams.h"

#ifdef ENABLE_WALLET

enum FeeRatePreset
{
    MINIMUM,
    MORE,
    WOW,
    AMAZE,
    MANY_GENEROUS,
    SUCH_EXPENSIVE
};

/** Estimate fee rate needed to get into the next nBlocks */
CFeeRate GetNovoFeeRate(int priority);
const std::string GetNovoPriorityLabel(int priority);
#endif // ENABLE_WALLET
CAmount GetNovoMinRelayFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree);
CAmount GetNovoDustFee(const std::vector<CTxOut> &vout, const CAmount dustLimit);

#endif // NOVO_NOVO_FEES_H
