# Contract Files Overview

## `Pairing.sol`
Elliptic curve pairing operations (BN256) for zkSNARK verification.

## `Groth16Verifier.sol`
Groth16 zkSNARK verifier using Pairing.sol primitives.

## `FairThunder_Stream_Utility.sol`
Helper functions: ZK verification, signature recovery, message hashing, and struct definitions.

## `FairThunder_Stream_Optimistic.sol`
Main FairThunder streaming contract with:
- Optimistic payment streams
- GPLP-based privacy settlement
- ZK staking authentication
- Three phases: Setup → Stream → Payout
