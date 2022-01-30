# vrf-oracle

## Overview

This project demonstrates a POC of a VRF oracle on Algorand's blockchain.

Written in `Go` and `pyteal` (TEAL 5).

It uses the same VRF implementation used by the `crypto` package in `go-algorand`.

The `Go` component is monitoring the network for new `request` calls to the smart-contract, computes the VRF and sends a
`respond` call to the smart-contract with the VRF output. It also looks for `cancel` calls and `closeout/clear` to
remove their correspondent requests from the queue. Its code can be found under `cmd/daemon`.

** Since this component was tested with Indexer version `2.6.4`, it also sends periodic zero amount transactions in
order to refresh results from `/v2/transactions` endpoint.

The smart-contract supports 4 commands:
- **request** - Request for VRF computation. Expects in a transactions group with service fee payment transaction.
- **respond** - Respond the VRF computation. Sent from an address used by the service, stored in global storage upon creation.
- **cancel** - Cancel a request. Sent by the same address used to send the request. Can only be approved if the request round is in the future.
- **withdraw_lost_funds** - If an address made a request and opt-out or cleared state before request the was handled, the service fee
  paid is considered "lost". The owner account (stored in global storage upon creation) can withdraw those funds.

`pyteal` code can be found in `pyteal/teal5.py`.

## Build

The libsodium submodule must be cloned down and built locally.

### Build libsodium from fork

Initialize the libsodium submodule

```sh
git submodule update --init --recursive
```

```sh
make build-libsodium
```

## Run

### Set environment variables

Set `AF_ALGOD_ADDRESS` and `AF_ALGOD_TOKEN` to point to a valid `algod` client.

Set `AF_IDX_ADDRESS` and `AF_IDX_TOKEN` to point to a valid `indexer` client.

Optionally set `VRF_LOG_LEVEL` to `DEBUG` or `INFO` (default is `WARN`).


### Supported arguments

This service can take the following arguments:
```
      --app-id uint               application ID (required)
      --dummy-app-id uint         dummy application ID for cost pooling (required)
      --round uint                the round to start scanning from (optional. default: current round)
      --service-mnemonic string   25-word mnemonic of the service for writing the response (required)
      --signing-mnemonic string   25-word mnemonic of the oracle for signing (required)
      --vrf-mnemonic string       25-word mnemonic of the oracle for computing vrf (required)
```

`dummy-app-id` should be the ID of an application which return 1 no matter what. It's used to pump-up the cost pool to allow calling `ed25519verify`.

`service-mnemonic` account should be funded to cover transaction fees.

### Execute

```sh
go run ./cmd run-daemon <ARGUMENTS>
```

## Test

### Prerequisites

- Launch instances of Algorand's `node` and `indexer` and set environment variables

This code was tested with `Sandbox`.

```sh
./sandbox version

algod version
12884901889
3.0.1.stable [rel/stable] (commit #b619b940)
go-algorand is licensed with AGPLv3.0
source code available at https://github.com/algorand/go-algorand

Indexer version
2.6.4 compiled at 2021-11-11T15:43:17+0000 from git hash 2d88932e2cf54fe62791502b646ffe7e60d4bfff (modified)

Postgres version
postgres (PostgreSQL) 13.4

CouchDB version
{"couchdb":"Welcome","version":"2.3.1","git_sha":"c298091a4","uuid":"a8f78b7f6460c9cf3ba4dff0fae7023f","features":["pluggable-storage-engines","scheduler"],"vendor":{"name":"The Apache Software Foundation"}}
```

### Create and fund accounts

In order to test, the following accounts should be created:
```
APP_CREATOR - account for the smart-contract app crator
OWNER - account to receive the fees payed for using the VRF service
VRF_SERVICE - account used by the VRF service to respond to requests
REQUESTER - account to send requests to the VRF smart-contract
SIGNING_ACCOUNT - account which responses are signed with its private-key
VRF_COMP_ACCOUNT - account which VRF proofs are computed with its private-key
```
`APP_CREATOR`, `OWNER`, `VRF_SERVICE` and `REQUESTER` should be funded to cover fees and reach minimum balance requirements.

### Create the smart-contract

```sh
go run ./cmd test create-app --app-creator-mnemonic <APP_CREATOR_MNEMONIC> \
--approval-program pyteal/vrf_oracle_approval.teal --clear-program pyteal/vrf_oracle_clear.teal --fee 500000 \
--owner <OWNER> --vrf-service-addr <VRF_SERVICE> --signing-pk-addr <SIGNING_ACCOUNT> --should-create-dummy
```
This creates 2 smart-contracts: the service smart-contract and a dummy one.

Both apps' IDs should be printed to the console and will be referred to as `APP_ID` and `DUMMY_APP_ID` in the next steps.


### Start the service

```sh
export VRF_LOG_LEVEL=debug  # optional but recommended
go run ./cmd run-daemon --signing-mnemonic <SIGNING_ACCOUNT_MNEMONIC> --vrf-mnemonic <VRF_COMP_ACCOUNT_MNEMONIC> \
--service-mnemonic <VRF_SERVICE_MNEMONIC> --dummy-app-id <DUMMY_APP_ID> --app-id <APP_ID>
```

### Opt-in the requester

```sh
$(goal_cmd) app optin --from <REQUESTER> --app-id <APP_ID>
```

### Send a request

```sh
go run ./cmd test request --app-id <APP_ID> --requester-mnemonic <REQUESTER_MNEMONIC> --block <BLOCK_NUMBER>
```
`BLOCK_NUMBER` is the block number from which the oracle should take the block seed from for the VRF input. It must be a future block (more than 10 rounds).

Once the service reached and handled `BLOCK_NUMBER`, the VRF output should in `REQUESTER`'s local storage, and the service
fee amount is transferred to `OWNER` account.

If `BLOCK_NUMBER` is more than 5 rounds in the future, the request can be canceled:

### Cancel a request

```sh
go run ./cmd test cancel --app-id <APP_ID> --requester-mnemonic <REQUESTER_MNEMONIC>
```

### Opt-out and clear state

If the `REQUESTER` opt-out or cleared state before request was handled, the service fee
he paid is considered "lost".

The `OWNER` account can withdraw cumulated "lost" funds:

```sh
go run ./cmd test withdraw-lost-funds --app-id <APP_ID> --owner-mnemonic <OWNER_MNEMONIC>
```