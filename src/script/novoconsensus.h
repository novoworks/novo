// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NOVO_NOVOCONSENSUS_H
#define NOVO_NOVOCONSENSUS_H

#include <stdint.h>

#if defined(BUILD_NOVO_INTERNAL) && defined(HAVE_CONFIG_H)
#include "config/novo-config.h"
  #if defined(_WIN32)
    #if defined(DLL_EXPORT)
      #if defined(HAVE_FUNC_ATTRIBUTE_DLLEXPORT)
        #define EXPORT_SYMBOL __declspec(dllexport)
      #else
        #define EXPORT_SYMBOL
      #endif
    #endif
  #elif defined(HAVE_FUNC_ATTRIBUTE_VISIBILITY)
    #define EXPORT_SYMBOL __attribute__ ((visibility ("default")))
  #endif
#elif defined(MSC_VER) && !defined(STATIC_LIBNOVOCONSENSUS)
  #define EXPORT_SYMBOL __declspec(dllimport)
#endif

#ifndef EXPORT_SYMBOL
  #define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define NOVOCONSENSUS_API_VER 1

typedef enum novoconsensus_error_t
{
    novoconsensus_ERR_OK = 0,
    novoconsensus_ERR_TX_INDEX,
    novoconsensus_ERR_TX_SIZE_MISMATCH,
    novoconsensus_ERR_TX_DESERIALIZE,
    novoconsensus_ERR_AMOUNT_REQUIRED,
    novoconsensus_ERR_INVALID_FLAGS,
} novoconsensus_error;

/** Script verification flags */
enum
{
    novoconsensus_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    novoconsensus_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), // enforce strict DER (BIP66) compliance
    novoconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY           = (1U << 4), // enforce NULLDUMMY (BIP147)
    novoconsensus_SCRIPT_FLAGS_VERIFY_ALL                 = novoconsensus_SCRIPT_FLAGS_VERIFY_DERSIG | novoconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY
};

/// Returns 1 if the input nIn of the serialized transaction pointed to by
/// txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
/// the additional constraints specified by flags.
/// If not NULL, err will contain an error/success code for the operation
EXPORT_SYMBOL int novoconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
                                                 const unsigned char *txTo        , unsigned int txToLen,
                                                 unsigned int nIn, unsigned int flags, novoconsensus_error* err);

EXPORT_SYMBOL int novoconsensus_verify_script_with_amount(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen, int64_t amount,
                                    const unsigned char *txTo        , unsigned int txToLen,
                                    unsigned int nIn, unsigned int flags, novoconsensus_error* err);

EXPORT_SYMBOL unsigned int novoconsensus_version();

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL

#endif // NOVO_NOVOCONSENSUS_H
