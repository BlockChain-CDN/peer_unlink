# Contract Files Overview

## `Pairing.sol`
Elliptic curve pairing operations (BN256) for zkSNARK verification.

## `Groth16Verifier.sol`
Groth16 zkSNARK verifier using Pairing.sol primitives.

## `FairStream_Utility.sol`
Helper functions: ZK verification, signature recovery, message hashing, and struct definitions.

## `FairStream_Optimistic.sol`
Main streaming contract with:
- Optimistic payment streams
- GPLP-based privacy settlement
- ZK staking authentication
- Three phases: Setup → Stream → Payout
