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

`pyteal` code can be found in `pyteal/main.py`.

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
      --starting-round uint           the round to start scanning from (optional. default: current round)
      --service-mnemonic string       25-word mnemonic of the service for writing the response (required)
      --vrf-mnemonic string           25-word mnemonic of the oracle for computing vrf (required)
```

`service-mnemonic` account should be funded to cover transaction fees.

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
12885645221
3.9.153509.dev [master] (commit #d7ed271c)
go-algorand is licensed with AGPLv3.0
source code available at https://github.com/algorand/go-algorand

Indexer version
2.13.0-dev.unknown compiled at 2022-08-07T09:39:45+0000 from git hash 6b61b08bcbaed5a994b9a68ac0bf40c1b902cca4 (modified)

Postgres version
postgres (PostgreSQL) 13.6
```

Use the following command to launch `Sandbox`:
```shell
./sandbox up source -v
```
Make sure that `algod` image is built from `go-algorand` commit [d7ed271c](https://github.com/algorand/go-algorand/tree/d7ed271c08b43708f07911589024a318deadca94) on branch `master`.

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
--vrf-mnemonic "boil frequent harvest donkey outside start thought road insane wine tooth fame assault any advice belt walk again proud debate culture omit diary able treat" \
--service-mnemonic "chat glory west mobile desk coin hockey swallow tilt chunk task model hidden helmet toddler tortoise always afraid absorb valve bar distance history absorb exercise" \
--app-creator-mnemonic "chat glory west mobile desk coin hockey swallow tilt chunk task model hidden helmet toddler tortoise always afraid absorb valve bar distance history absorb exercise" \
--approval-program pyteal/vrf_beacon_abi_approval.teal \
--clear-program pyteal/vrf_beacon_abi_clear.teal \
--starting-round 8
```
