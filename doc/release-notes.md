# Release Notes for Novo version 0.3.0

It mainly contains changes listed below:

1. Hard fork scheduled for height 290000 to enable native token support on mainnet
2. Spam attack protection (all policy-level changes, not consensus):
   1. Increase minimum fee rate for relayed/mined transactions from 0.8 to 25 Novo per KB
   2. Restrict maximum size for relayed/mined transactions to 5MB from 8MB
   3. Increase maximum block size from 8MB to 128MB
   4. Increase dust limit from 0.4368 to 5 Novo
