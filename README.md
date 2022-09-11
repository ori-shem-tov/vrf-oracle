# vrf-oracle

## Overview

This project demonstrates a POC of a VRF oracle on Algorand's blockchain.

The project has two parts:
* VRF smart contract in `pyteal/main.py` (PyTeal)
* VRF service in `Go`

It uses the same VRF implementation used by the `crypto` package in `go-algorand`.

The VRF service acts as a beacon and computes a pseudo random value (using VRF) for every round that is a multiple of 8. Its code can be found under `cmd/daemon`.

** It also sends periodic zero amount transactions as a workaround for a weird issue where no blocks are added when there are no transactions.

Design is detailed in [./DESIGN.md](DESIGN.md).

## Requirements

### Requirements for smart contract

* Python 3.10
* PyTeal 0.17.0

### Requirements for VRF service

Go 1.14 or newer, as well as usual tools to allow compilation (C compiler, autoconf, make, ...)

### Requirements for developing

- `pylint`: `python3 -m pip install pylint`
- `golangci-lint`
    - on Ubuntu: https://golangci-lint.run/usage/install/#local-installation
      (note that you must have a single folder in your `$GOPATH` if you run the proposed command)
    - on macOS: `brew install golangci-lint`
- `gosec`
    - on Ubuntu: https://github.com/securego/gosec#local-installation
    - on macOS: `brew install gosec`


## Build

### Build libsodium from fork

```sh
git submodule update --init
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

`run-daemon` does not re-generate the TEAL files from PyTEAL.
You need to re-generate those when updating the smart contract.

```
cd pyteal
pip install -r requirements.txt
python3 main.py
```

## Test

### Prerequisites

- Launch instance of Algorand's `node` and set environment variables

This code currently (in Aug 2022) requires the use of sandbox on the beta config.

```shell
$ ./sandbox version
algod version
WARN[0000] The "INDEXER_ENABLE_ALL_PARAMETERS" variable is not set. Defaulting to a blank string.
12885491713
3.9.1.beta [rel/beta] (commit #379ec4f8)
go-algorand is licensed with AGPLv3.0
source code available at https://github.com/algorand/go-algorand

Indexer version
WARN[0000] The "INDEXER_ENABLE_ALL_PARAMETERS" variable is not set. Defaulting to a blank string.
2.13.0-dev.unknown compiled at 2022-08-19T14:22:17+0000 from git hash dc8f994530ad84ac84d3a21ad7b8965e06e718f8 (modified)

Postgres version
WARN[0000] The "INDEXER_ENABLE_ALL_PARAMETERS" variable is not set. Defaulting to a blank string.
postgres (PostgreSQL) 13.3
```

Use the following command to launch `Sandbox`:
```shell
./sandbox up beta -v
```

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

## Misc notes

We use a version of PyTeal that merge https://github.com/algorand/pyteal/pull/514
When this PR is merged to a released version of PyTeal, `pyteal/requirements.txt` needs to be updated.