# Release Notes for Novo version 0.1.0

The source code of Novo is released regularly for public audits. It complies with the [Semantic Versioning (semver.org)](https://semver.org/).

- For bug fixes and minor improvements, please submit Pull Requests directly.
- For significant enhancements, please write a draft so that we can discuss them more deeply.

## Novo v0.1.0

this is the initial source code release of Novo.

It mainly contains changes listed below:

### Feature changes:

1. The mining algorithm is changed to Tagged SHA256 (with 'PoW' tagged).
2. The difficulty adjustment algorithm is changed to ASERT.
3. The block interval is set to 150 seconds.
4. The decimal is four digits.
5. The initial block reward is 2,000,000 NOVO.
6. The max total supply is 840,000,000,000 NOVO.
7. The hashing of TXID is now based on Rich Transaction Body.
8. The block size limit is 8MB initially.
9. The maximum transaction size is 1MB initially.
10. The script size is limited to 10KB (in policy which is customizable)
11. The default fee is 8 sat/byte for ordinary transactions.

### Implementation changes:

1. Use different Magic Numbers for network messages and data persistence.
2. The minimum transaction size (`MIN_TX_SIZE_CONSENSUS`) is set to 65 bytes.
3.  `MAX_FUTURE_BLOCK_TIME` is set to 150 seconds.
