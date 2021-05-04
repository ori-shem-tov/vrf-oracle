package main

import (
	"context"
	"fmt"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	addressAStr      string
	addressBStr      string
	counterHexStr	 string
)

func init() {
	setLogger()

	settlementPhaseCmd.Flags().Uint64Var(&appID, "app-id", 0,
		"Game app ID")
	markFlagRequired(settlementPhaseCmd.Flags(), "app-id")

	settlementPhaseCmd.Flags().StringVar(&addressAStr, "address-a", "", "address of player A")
	markFlagRequired(settlementPhaseCmd.Flags(), "address-a")

	settlementPhaseCmd.Flags().StringVar(&addressBStr, "address-b", "", "address of player B")
	markFlagRequired(settlementPhaseCmd.Flags(), "address-b")

	settlementPhaseCmd.Flags().StringVar(&counterHexStr, "counter-hex-string", "",
		"a string representation of an 8 byte hex")
	markFlagRequired(settlementPhaseCmd.Flags(), "counter-hex-string")
}

func makeSettlementTransactionsGroup(appID uint64, to, player string, escrowLsig types.LogicSig,
	suggestedParams types.SuggestedParams) ([]byte, error) {
	escrowAddress := crypto.AddressFromProgram(escrowLsig.Logic)
	appArgs := [][]byte{
		[]byte(player),
	}
	appCallClose, err := future.MakeApplicationCloseOutTx(
		appID,
		appArgs,
		nil,
		nil,
		nil,
		suggestedParams,
		escrowAddress,
		nil,
		types.Digest{},
		[32]byte{},
		types.Address{},
	)
	if err != nil {
		return nil, err
	}
	paymentClose, err := future.MakePaymentTxn(
		escrowAddress.String(),
		escrowAddress.String(),
		0,
		nil,
		to,
		suggestedParams,
	)
	if err != nil {
		return nil, err
	}
	group, err := transaction.AssignGroupID([]types.Transaction{appCallClose, paymentClose}, "")
	if err != nil {
		return nil, err
	}
	_, signedAppCallClose, err := crypto.SignLogicsigTransaction(escrowLsig, group[0])
	if err != nil {
		return nil, err
	}
	_, signedPaymentClose, err := crypto.SignLogicsigTransaction(escrowLsig, group[1])
	if err != nil {
		return nil, err
	}
	signedGroup := append(signedAppCallClose, signedPaymentClose...)
	return signedGroup, nil
}

var settlementPhaseCmd = &cobra.Command{
	Use:   "settlement",
	Short: "test settlement phase",
	Run: func(cmd *cobra.Command, args []string) {
		err := testEnvironmentVariables()
		if err != nil {
			log.Error(err)
			return
		}
		algodClient, _, err := initClients(algodAddress, algodToken, indexerAddress, indexerToken)
		if err != nil {
			log.Error(err)
			return
		}
		suggestedParams, err := algodClient.SuggestedParams().Do(context.Background())
		if err != nil {
			log.Error(err)
			return
		}
		addressA, err := types.DecodeAddress(addressAStr)
		if err != nil {
			log.Error(err)
			return
		}
		addressB, err := types.DecodeAddress(addressBStr)
		if err != nil {
			log.Error(err)
			return
		}
		if len(counterHexStr) != 18 || counterHexStr[:2] != "0x" {
			log.Errorf("counter-hex-string is not a valid 8 byte hex")
			return
		}
		escrowTealParams := EscrowTealParams{
			AddressA:   addressA,
			AddressB:   addressB,
			CounterHex: counterHexStr,
		}
		escrowProgram, err := CompileEscrow(escrowTealParams, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		logicArgs := [][]byte{
			[]byte("settlement"),
		}
		escrowLsig, err := crypto.MakeLogicSig(escrowProgram, logicArgs, nil, crypto.MultisigAccount{})
		if err != nil {
			log.Error(err)
			return
		}
		signedSettlementA, err := makeSettlementTransactionsGroup(appID, addressAStr, "A", escrowLsig, suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		signedSettlementB, err := makeSettlementTransactionsGroup(appID, addressBStr, "B", escrowLsig, suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		txIDA, errA := algodClient.SendRawTransaction(signedSettlementA).Do(context.Background())
		txIDB, errB := algodClient.SendRawTransaction(signedSettlementB).Do(context.Background())
		if errA != nil && errB != nil {
			log.Errorf("Error with sending settlement transactions: %v, %v", errA, errB)
			return
		}
		if errA == nil && errB == nil {
			log.Errorf("fatal: both A and B settled, this should never happen txIDA: %s, txIDb: %s", txIDA, txIDB)
			return
		}
		if errB != nil {
			fmt.Println("A won!")
		} else {
			fmt.Println("B won!")
		}

	},
}

