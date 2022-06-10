BIPs that are implemented by Novo (up-to-date up to **v0.13.0**):

* [`BIP 9`](bips/bip-0009.mediawiki): The changes allowing multiple soft-forks to be deployed in parallel have been implemented since **v0.12.1**  ([PR #7575](https://github.com/bitcoin/bitcoin/pull/7575))
* [`BIP 11`](bips/bip-0011.mediawiki): Multisig outputs are standard since **v0.6.0** ([PR #669](https://github.com/bitcoin/bitcoin/pull/669)).
* [`BIP 14`](bips/bip-0014.mediawiki): The subversion string is being used as User Agent since **v0.6.0** ([PR #669](https://github.com/bitcoin/bitcoin/pull/669)).
* [`BIP 22`](bips/bip-0022.mediawiki): The 'getblocktemplate' (GBT) RPC protocol for mining has been implemented since **v0.7.0** ([PR #936](https://github.com/bitcoin/bitcoin/pull/936)).
* [`BIP 23`](bips/bip-0023.mediawiki): Some extensions to GBT have been implemented since **v0.10.0rc1**, including longpolling and block proposals ([PR #1816](https://github.com/bitcoin/bitcoin/pull/1816)).
* [`BIP 31`](bips/bip-0031.mediawiki): The 'pong' protocol message (and the protocol version bump to 60001) has been implemented since **v0.6.1** ([PR #1081](https://github.com/bitcoin/bitcoin/pull/1081)).
* [`BIP 32`](bips/bip-0032.mediawiki): Hierarchical Deterministic Wallets has been implemented since **v0.13.0** ([PR #8035](https://github.com/bitcoin/bitcoin/pull/8035)).
* [`BIP 34`](bips/bip-0034.mediawiki): The rule that requires blocks to contain their height (number) in the coinbase input, and the introduction of version 2 blocks has been implemented since **v0.7.0**. The rule took effect for version 2 blocks as of *block 224413* (March 5th 2013), and version 1 blocks are no longer allowed since *block 227931* (March 25th 2013) ([PR #1526](https://github.com/bitcoin/bitcoin/pull/1526)).
* [`BIP 35`](bips/bip-0035.mediawiki): The 'mempool' protocol message (and the protocol version bump to 60002) has been implemented since **v0.7.0** ([PR #1641](https://github.com/bitcoin/bitcoin/pull/1641)).
* [`BIP 37`](bips/bip-0037.mediawiki): The bloom filtering for transaction relaying, partial merkle trees for blocks, and the protocol version bump to 70001 (enabling low-bandwidth SPV clients) has been implemented since **v0.8.0** ([PR #1795](https://github.com/bitcoin/bitcoin/pull/1795)).
* [`BIP 42`](bips/bip-0042.mediawiki): The bug that would have caused the subsidy schedule to resume after block 13440000 was fixed in **v0.9.2** ([PR #3842](https://github.com/bitcoin/bitcoin/pull/3842)).
* [`BIP 61`](bips/bip-0061.mediawiki): The 'reject' protocol message (and the protocol version bump to 70002) was added in **v0.9.0** ([PR #3185](https://github.com/bitcoin/bitcoin/pull/3185)).
* [`BIP 66`](bips/bip-0066.mediawiki): The strict DER rules and associated version 3 blocks have been implemented since **v0.10.0** ([PR #5713](https://github.com/bitcoin/bitcoin/pull/5713)).
* [`BIP 90`](bips/bip-0090.mediawiki): Trigger mechanism for activation of BIPs 34, 65, and 66 has been simplified to block height checks since **v0.14.0** ([PR #8391](https://github.com/bitcoin/bitcoin/pull/8391)).
* [`BIP 111`](bips/bip-0111.mediawiki): `NODE_BLOOM` service bit added, and enforced for all peer versions as of **v0.13.0** ([PR #6579](https://github.com/bitcoin/bitcoin/pull/6579) and [PR #6641](https://github.com/bitcoin/bitcoin/pull/6641)).
* [`BIP 113`](bips/bip-0113.mediawiki): Median time past lock-time calculations have been implemented since **v0.12.1** ([PR #6566](https://github.com/bitcoin/bitcoin/pull/6566)) and have been activated since *block 419328*.
* [`BIP 130`](bips/bip-0130.mediawiki): direct headers announcement is negotiated with peer versions `>=70012` as of **v0.12.0** ([PR 6494](https://github.com/bitcoin/bitcoin/pull/6494)).
* [`BIP 133`](bips/bip-0133.mediawiki): feefilter messages are respected and sent for peer versions `>=70013` as of **v0.13.0** ([PR 7542](https://github.com/bitcoin/bitcoin/pull/7542)).
* [`BIP 147`](bips/bip-0147.mediawiki): NULLDUMMY softfork as of **v0.13.1** ([PR 8636](https://github.com/bitcoin/bitcoin/pull/8636) and [PR 8937](https://github.com/bitcoin/bitcoin/pull/8937)). BIP 147 has been removed in Novo.
* [`BIP 152`](bips/bip-0152.mediawiki): Compact block transfer and related optimizations are used as of **v0.13.0** ([PR 8068](https://github.com/bitcoin/bitcoin/pull/8068)).
