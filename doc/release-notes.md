# Release Notes for Novo version 0.2.0

Novo version 0.2.0 is released.

<<<<<<< HEAD
1. Hard fork scheduled for height 280000 to enable native token support on mainnet
2. Spam attack protection (all policy-level changes, not consensus):
   1. Increase minimum fee rate for relayed/mined transactions from 0.8 to 25 Novo per KB
   2. Restrict maximum size for relayed/mined transactions to 1.25MB
   3. Default maximum block creation size set to 1.5MB; hard cap remains at 8MB
   4. Increase dust limit from 0.4368 to 5 Novo
=======
1. Opcode being compatible with v0.1.2
2. Dust is now a fixed value (0.4368 Novo)
3. FeeRate is set to 0.8 Novo/KB, consistent with v0.1.2.
4. RPC is modified and basically compatible with v0.1.2.
5. GUI is removed.
6. Alert system is removed.
7. Hard fork is scheduled at height 130000 to disable RichTXID.
>>>>>>> parent of 0c5bf3d (0.3.0)
