package main

import (
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/types"
	"strconv"
	"strings"
)

type EscrowTealParams struct {
	AddressA types.Address
	AddressB types.Address
	CounterHex string
}

func (escrowTealParams *EscrowTealParams) Validate() error {
	var errors []string
	_, err := strconv.ParseUint(escrowTealParams.CounterHex, 0, 64)
	if err != nil || len(escrowTealParams.CounterHex) != 18 || escrowTealParams.CounterHex[:2] != "0x" {
		errors = append(errors, "CounterHex should be a string of 8 byte hex number")
	}

	if len(errors) != 0 {
		return fmt.Errorf(strings.Join(errors, ", "))
	}
	return nil
}

// CompileEscrow compiles ths escrow teal program
func CompileEscrow(escrowTealParams EscrowTealParams, algodClient *algod.Client) ([]byte, error) {
	return CompileTeal(&escrowTealParams, EscrowTealTemplate, algodClient)
}
