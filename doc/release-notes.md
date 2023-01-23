# Release Notes for Novo version 0.3.0

**This is a mandatory update!**

It mainly contains changes listed below:

1. Hard fork scheduled for height 290000 to enable native token support on mainnet
2. Spam attack protection (all policy-level changes, not consensus):
   1. Increase minimum fee rate for relayed/mined transactions from 0.8 to 25 Novo per KB
   2. Restrict maximum size for relayed/mined transactions to 1.25MB
   3. Default maximum block creation size set to 1.5MB; hard cap remains at 8MB
   4. Increase dust limit from 0.4368 to 5 Novo
