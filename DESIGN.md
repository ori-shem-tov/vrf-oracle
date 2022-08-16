# Randomness beacon on Algorand

## Introduction
Generating a source of trusted and secure randomness is not an easy task, especially on-chain, yet having one is necessary for transparency of decentralized applications that depend on randomized processes. Crucially, for most on-chain applications it is not enough to use "random looking" quantities (such as the block seed) as sources of randomness. Block proposers have partial control over these quantities, making it possible for rogue block proposers to break applications that depend on these sources being unpredictable.

This document describes the requirements for building a verifiable randomness beacon on the Algorand blockchain to be used by Algorand's smart-contracts.

## Design
The system consists of two main components, one is off-chain (annotated **the service**) and one is on-chain (annotated **the smart contract** or **the SC**) communicating with each other through an API provider of Algod.

### The service
The service holds a VRF secret key, and uses it to periodically compute a VRF proof (implemented in https://github.com/algorand/libsodium). A new VRF proof is computed once every 8 rounds and then submitted to the smart-contract.

#### Specs:
- The input to the VRF computation is **round|block_seed** where:
  - **round** is the round of the computation. Must be a multiple of X.
  - **block_seed** is the seed taken from block number == round
  - **|** is the concatenation operator
- The VRF secret key used by the service must be kept secure and available (see below).

Note that the VRF proof can only be computed by the service after the block number corresponding to the specified **round** was committed to the network, since the **block_seed** is not available before that.

### The smart contract
The smart contract adheres to [ARC-4: Algorand Application Binary Interface (ABI)](https://arc.algorand.foundation/ARCs/arc-0004) and [ARC-21: Round based datafeed oracles on Algorand](https://github.com/algorandfoundation/ARCs/pull/76)

#### It implements the following methods:
- **create_app(uint64,byte[80],address)void**:  
**create_app** is called only upon creation of the SC. It initiates the SC's data structure (see below) and submits the first VRF proof.
- **submit(uint64,byte[80])void**:  
**submit** verifies the VRF proofs and stores the corresponding VRF outputs in global storage.
- **get(uint64,byte[])byte[32]**:  
**get** returns a pseudo-random value derived from the stored VRF output corresponding to a given round or an empty byte array in case there's no value to return.
- **mustGet(uint64,byte[])byte[32]**:  
**mustGet** logic is the same as **get**, but panics in case there's no value to return.


