# vrf-oracle

## Build
### Build libsodium from fork
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
      --oracle-fee uint           the fee payed to the oracle for its service in MicroAlgos (optional) (default 1000)
      --owner string              the oracle's owner address (required)
      --round uint                the round to start scanning from (optional. default: current round)
      --signing-mnemonic string   25-word mnemonic of the oracle for signing (required)
      --vrf-mnemonic string       25-word mnemonic of the oracle for computing vrf (required)
```

### Execute
```sh
go run . <ARGUMENTS>
```
