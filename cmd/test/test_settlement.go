package test

import (
	"context"
	"fmt"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	"github.com/ori-shem-tov/vrf-oracle/teal/compile"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	addressAStr      string
	addressBStr      string
	counterHexStr	 string
)

func init() {
	daemon.SetLogger()

	settlementPhaseCmd.Flags().Uint64Var(&appID, "app-id", 0,
		"Game app ID")
	daemon.MarkFlagRequired(settlementPhaseCmd.Flags(), "app-id")

	settlementPhaseCmd.Flags().StringVar(&addressAStr, "address-a", "", "address of player A")
	daemon.MarkFlagRequired(settlementPhaseCmd.Flags(), "address-a")

	settlementPhaseCmd.Flags().StringVar(&addressBStr, "address-b", "", "address of player B")
	daemon.MarkFlagRequired(settlementPhaseCmd.Flags(), "address-b")

	settlementPhaseCmd.Flags().StringVar(&counterHexStr, "counter-hex-string", "",
		"a string representation of an 8 byte hex")
	daemon.MarkFlagRequired(settlementPhaseCmd.Flags(), "counter-hex-string")
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
		err := daemon.TestEnvironmentVariables()
		if err != nil {
			log.Error(err)
			return
		}
		algodClient, _, err := daemon.InitClients(daemon.AlgodAddress, daemon.AlgodToken, daemon.IndexerAddress, daemon.IndexerToken)
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
		escrowTealParams := compile.EscrowTealParams{
			AddressA:   addressA,
			AddressB:   addressB,
			CounterHex: counterHexStr,
		}
		escrowProgram, err := compile.CompileEscrow(escrowTealParams, algodClient)
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

