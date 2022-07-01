# vrf-oracle

## Overview

This project demonstrates a POC of a VRF oracle on Algorand's blockchain.

Written in `Go` and `pyteal`.

It uses the same VRF implementation used by the `crypto` package in `go-algorand`.

The `Go` component acts as a beacon and computes a pseudo random value (using VRF) for every round that is a multiple of 8. Its code can be found under `cmd/daemon`.

** It also sends periodic zero amount transactions as a workaround for a weird issue where no blocks are added when there are no transactions.

The smart-contract supports 4 commands:
- **request** - Request for VRF value.
- **respond** - Respond the VRF computation. Sent from an address used by the service, stored in global storage upon creation.

`pyteal` code can be found in `pyteal/teal5.py`.

Please note that since the smart contract is using the `vrf_verify` and `block` TEAL opcodes (that are not in production and not supported by `pyteal` at the time this was written) the `pyteal/teal5.py` and `pyteal/vrf_beacon_approval.teal` are not synced.

## Build

### Build libsodium from fork

```sh
make build-libsodium
```

## Run

### Set environment variables

Set `AF_ALGOD_ADDRESS` and `AF_ALGOD_TOKEN` to point to a valid `algod` client.

Optionally set `VRF_LOG_LEVEL` to `DEBUG` or `INFO` (default is `WARN`).


### Supported arguments

This service can take the following arguments:
```
      --app-creator-mnemonic string   25-word mnemonic of the app creator (required)
      --approval-program string       TEAL script of the approval program (required)
      --clear-program string          TEAL script of the clear program (required)
      --round uint                    the round to start scanning from (optional. default: current round)
      --service-mnemonic string       25-word mnemonic of the service for writing the response (required)
      --signing-mnemonic string       25-word mnemonic of the oracle for signing (required)
      --vrf-mnemonic string           25-word mnemonic of the oracle for computing vrf (required)
```

`service-mnemonic` account should be funded to cover transaction fees.

Please note that `signing-mnemonic` account is used to sign the VRF proof and that the signature is passed to the smart contract **but the smart contract is not validating it**. Therefore, the `signing-mnemonic` arg should be **REMOVED** in the final implementation.

### Execute

```sh
go run ./cmd run-daemon <ARGUMENTS>
```

## Test

### Prerequisites

- Launch instance of Algorand's `node` and set environment variables

This code was tested with `Sandbox`'s [fork](https://github.com/ori-shem-tov/sandbox) on branch `avm-randomness`.

```shell
./sandbox version

algod version
12885379288
3.5.149720.dev [avm-randomness] (commit #2d07bd0e)
go-algorand is licensed with AGPLv3.0
source code available at https://github.com/algorand/go-algorand

Indexer version
2.12.1-dev.unknown compiled at 2022-06-29T17:41:41+0000 from git hash 03b140cfdc964bedfe59667eeda2f9f16ab3a8d1 (modified)

Postgres version
postgres (PostgreSQL) 13.6
```

Use the following command to launch `Sandbox`:
```shell
./sandbox up source -v
```
Make sure that `algod` image is built from `go-algorand`'s [fork](https://github.com/ori-shem-tov/go-algorand) on branch `avm-randomness`.

Set environment variables:
```shell
export AF_ALGOD_ADDRESS=http://localhost:4001;
export AF_ALGOD_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
```

### Fund the service account

Using `./sandbox goal clerk send` command, fund the service account `LWOXAHEF32ISGGQSQTOFFTVSVUGJIRRFSIJYRFVL4PK4KS7MNG4SBWKYK4`

### Start the service

```shell
export VRF_LOG_LEVEL=debug  # optional but recommended
go run ./cmd run-daemon \
--signing-mnemonic "tobacco bottom online arch street good gain sting wrap power scissors unique common shoe sunny unaware bind jewel stock polar radio world liberty about village" \
--vrf-mnemonic "boil frequent harvest donkey outside start thought road insane wine tooth fame assault any advice belt walk again proud debate culture omit diary able treat" \
--service-mnemonic "chat glory west mobile desk coin hockey swallow tilt chunk task model hidden helmet toddler tortoise always afraid absorb valve bar distance history absorb exercise" \
--app-creator-mnemonic "chat glory west mobile desk coin hockey swallow tilt chunk task model hidden helmet toddler tortoise always afraid absorb valve bar distance history absorb exercise" \
--approval-program pyteal/vrf_beacon_approval.teal \
--clear-program pyteal/vrf_beacon_clear.teal
```
