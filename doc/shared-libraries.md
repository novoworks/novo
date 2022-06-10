Shared Libraries
================

## novoconsensus

The purpose of this library is to make the verification functionality that is critical to Novo's consensus available to other applications, e.g. to language bindings.

### API

The interface is defined in the C header `novoconsensus.h` located in  `src/script/novoconsensus.h`.

#### Version

`novoconsensus_version` returns an `unsigned int` with the API version *(currently at an experimental `0`)*.

#### Script Validation

`novoconsensus_verify_script` returns an `int` with the status of the verification. It will be `1` if the input script correctly spends the previous output `scriptPubKey`.

##### Parameters
- `const unsigned char *scriptPubKey` - The previous output script that encumbers spending.
- `unsigned int scriptPubKeyLen` - The number of bytes for the `scriptPubKey`.
- `const unsigned char *txTo` - The transaction with the input that is spending the previous output.
- `unsigned int txToLen` - The number of bytes for the `txTo`.
- `unsigned int nIn` - The index of the input in `txTo` that spends the `scriptPubKey`.
- `unsigned int flags` - The script validation flags *(see below)*.
- `novoconsensus_error* err` - Will have the error/success code for the operation *(see below)*.

##### Script Flags
- `novoconsensus_SCRIPT_FLAGS_VERIFY_NONE`
- `novoconsensus_SCRIPT_FLAGS_VERIFY_P2SH` - Evaluate P2SH ([BIP16](bips/bip-0016.mediawiki)) subscripts
- `novoconsensus_SCRIPT_FLAGS_VERIFY_DERSIG` - Enforce strict DER ([BIP66](bips/bip-0066.mediawiki)) compliance
- `novoconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY` - Enforce NULLDUMMY ([BIP147](bips/bip-0147.mediawiki))

##### Errors
- `novoconsensus_ERR_OK` - No errors with input parameters *(see the return value of `novoconsensus_verify_script` for the verification status)*
- `novoconsensus_ERR_TX_INDEX` - An invalid index for `txTo`
- `novoconsensus_ERR_TX_SIZE_MISMATCH` - `txToLen` did not match with the size of `txTo`
- `novoconsensus_ERR_DESERIALIZE` - An error deserializing `txTo`
- `novoconsensus_ERR_AMOUNT_REQUIRED` - Input amount is required if WITNESS is used
