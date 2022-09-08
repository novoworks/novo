# Release Notes for Novo version 0.2.0

Novo version 0.2.0 is now available from:

  <https://novonode.org>

To ensure everything is MIT licensed, the newly re-opened Novo source code repository is entirely re-written based on a variation of Dogecoin.

It mainly contains changes listed below:

1. Opcode being compatible with v0.1.2
2. Dust is now a fixed value (0.4368 Novo)
3. FeeRate is set to 0.8 Novo/KB, consistent with v0.1.2.
4. RPC is modified and basically compatible with v0.1.2.
5. GUI is removed.
6. Alert system is removed.
7. Hard fork is scheduled at height 130000 to disable RichTXID.
8. Block files are not compatible with earlier versions. Please remove old files(except wallet.dat), or start with -reindex to recover.
