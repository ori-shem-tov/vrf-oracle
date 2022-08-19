# Randomness beacon on Algorand

## Introduction

Generating a source of trusted and secure randomness is not an easy task, especially on-chain, yet having one is necessary for transparency of decentralized applications that depend on randomized processes. Crucially, for most on-chain applications it is not enough to use "random looking" quantities (such as the block seed) as sources of randomness. Block proposers have partial control over these quantities, making it possible for rogue block proposers to break applications that depend on these sources being unpredictable.

This document describes the design of the randomness beacon in this repo as well as its rationale.

## Design

The system consists of two main components, one is off-chain (annotated **the service**) and one is on-chain (annotated **the smart contract** or **the SC**). The service is connected to the blockchain via an algod endpoint.

### The service

The service holds a VRF secret key, and uses it to periodically compute a VRF proof (implemented in https://github.com/algorand/libsodium). 
A new VRF proof is computed once every 8 rounds and then submitted to the smart contract.

Specs:  
- The input to the VRF computation is `SHA-512/256(round|block_seed)` where:
  - `round` is the round of the computation (8 bytes, big endian). Must be a multiple of 8.
  - `block_seed` is the seed taken from block number == `round` (8 bytes, big endian).
  - `|` is the concatenation operator.
- The VRF secret key used by the service must be kept secure and available (see below).

Note that the VRF proof can only be computed by the service after the block number corresponding to the specified `round` was committed to the network, since the `block_seed` is not available before that.
Under normal circumstances (see note *), the block seed is unpredictable (except to the block proposer), and VRF output corresponding to the VRF proof cannot be guessed by the VRF service.

In addition, the VRF output looks uniformly random to anyone not knowing the secret key until the VRF proof is revealed.
This means block proposers cannot bias it without colluding with the VRF service.

Note *: In some circumstances, for example in some cases when the block proposer is misbehaving, the block seed may be computed as a hash of a previous block seed (as opposed to a VRF output under a VRF key known by the block proposer, which makes it unpredictable). That is why, if very high security is required, it is recommended to smart contracts to use a randomness output for a far away round (compared to the current round).

### The smart contract

The smart contract adheres to [ARC-4: Algorand Application Binary Interface (ABI)](https://arc.algorand.foundation/ARCs/arc-0004) and [ARC-21: Round based datafeed oracles on Algorand](https://github.com/algorandfoundation/ARCs/pull/76).

Concretely, anyone can submit to the smart contract VRF proofs for (multiple of 8) rounds (in order). 
The smart contract verifies them and stores the ones for the last 189 rounds. 
Then, any other smart contract can call the smart contract to derive random outputs from any rounds for which a matching stored value exist (see below for details).

#### High-Level Rationale

The reason why submission of the VRF proofs and retrieval of random outputs is two-fold:
1. Without this separation, every user of the randomness would need to provide the VRF proof for the given round, which requires some additional off-chain mechanism.
2. Verifying a VRF proof is very costly (in terms of opcodes). This separation allows verification only once per round submitted.

The restriction to storing 189 values is due to global state size restriction on Algorand.
Due to that, we only require VRF proofs to be given every 8 rounds, which means that values can be retrieved up to 189*8 rounds in the past.

#### ABI Interface

The smart contract implements the following methods:  
- `create_app(uint64,byte[80],byte[32])void`:  
  `create_app` is called only upon creation of the SC. It initiates the SC's data structure (see below) and submits the first VRF proof.
- `submit(uint64,byte[80])void`:  
  `submit` verifies the VRF proofs and stores the corresponding VRF outputs in global storage.
- `get(uint64,byte[])byte[]`:  
  `get` returns a 32-byte pseudo-random value derived from the stored VRF output corresponding to a given round or an empty byte array in case there's no value to return.
  Note that the ABI convention prefixes the output by its length (as the type is `[]byte`), that is `0x0020`. 
- `must_get(uint64,byte[])byte[]`:  
  `must_get` logic is the same as `get`, but panics in case there's no value to return.

Note that `submit` has a high opcode cost (higher than 700).
It needs to be called in a group of enough transactions so the available opcode cost is high enough.

#### Data storage: Indexes, Slots and Cells

At the time this document was written, a smart contract on Algorand can store up to 64 key-value pairs in its global storage (annotated **slots**) where each slot can store up to 128 bytes.

The SC stores the following data:  
- The **public key** needed for verifying the VRF proofs.
- The rounds of **first** and **last** stored values (when the contract is initialized with its first VRF proof, these two values are equal, then they diverge until first-last becomes equal to 188*8).
- Up to 189 last VRF outputs, depends on how many rounds the service is alive (see **Disaster recovery**).

The **public key** and the **first** and **last** rounds are stored in the **main** slot which is the slot with an empty string as its key. The value stored in this slot is `last_round|first_round|public_key` where the `|` is the concatenation operator and `last_round` and `first_round` are encoded as 8 bytes in big endian.

The VRF outputs are stored in a circular array built on top of the remaining 63 slots, as follows:  
- Each slot has a 8-byte key in range [0-63] (big endian, 0-padded)
- Each slot is divided into 3 cells, 32 bytes each.

>TODO: maybe add visuals

The result is a circular array with 189 indexes where each index `i` is located in slot `floor(i/3)` and in cell `i%3`.

Since VRF outputs have 64 bytes, VRF outputs are first truncated to 32 bytes.
To store a VRF output for round $round$ in a cell, the SC finds the slot index based on the round of the VRF proof $$\frac{\frac{round}{8}\bmod{189}}{3}$$ and the cell index $$\frac{round}{8}\bmod{189}\bmod{3}.$$ 
Note that the round must be a multiple of 8, which is enforced by the SC.

#### Getting randomness from the SC

In order to get randomness from the SC, a round `round` must be supplied as input.
The caller can also specify an optional user input `user_input`.
The returned value is:

```
SHA3-256(VRF_output[round_ceil8] | round | user_input)
```

where:
* `round_ceil8` is the lowest multiple of 8 larger or equal to `round`
* `VRF_output[round_ceil8]` is the corresponding VRF output stored in the smart contract
* `round` is the actual round asked, encoded as an 8-byte string in big endian.
* `user_input` is the (potentially empty) user input

##### Rationale

The inclusion of the `round` as input to the hash is to ensure that each round (corresponding to the same `round_ceil8`) yield a different random value.

The use of SHA3 (as opposed to SHA2) is because `SHA3(key | input)` is a secure PRF/keyed MAC.

The use of ceiling up (for `round_ceil8`) is to ensure that the random value for the round could not be computed before the input round.

### Disaster recovery

The SC expects every submitted VRF proof to be generated from the consecutive round to the last stored round that is a multiple of 8. This means that there cannot be gaps in between submission and if, for any reason, the service fails to submit a VRF proof it cannot skip and must try again. In addition, at the time this document was written, a smart contract on Algorand can only retrieve the seed of the previous 1000 blocks, meaning the service has only a finite number of rounds to recover in case of failure. For that reason, in case a block seed cannot be retrieved on-chain (more than 1000 blocks were added) the SC will allow the service to restart with a new round as long at its at least 984 round less then the current round.

984 is chosen to give some flexbility to the service while trying to ensure that the gap (where no random values can be computed) is as small as possible.

### Security measures

All private keys must be stored and handled to ensure a very high level of security and availability. In particular, they should never be stored with the code, best practices must be strictly followed.

Understanding consequences:
* Security: a collusion between the block proposer and someone who knows the VRF secret key can influence the randomness. Hence, if the VRF is stolen and used by a rogue block proposer, the randomness service will be broken.
* Availability: if the VRF key is not securely backed up and lost, the service will stop forever and the oracle users may be forever locked out.

### Notes for randomness users

TO BE WRITTEN: but should include: importance of committing to future round (as much in advance as possible), allowing update of smart contract (or supporting gaps/lose of randomness), ...



