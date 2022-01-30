package test

import (
	"context"

	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	daemon.SetLogger()

	withdrawLostFundsCmd.Flags().Uint64Var(&appID, "app-id", 0,
		"Game app ID")
	withdrawLostFundsCmd.MarkFlagRequired("app-id")

	withdrawLostFundsCmd.Flags().StringVar(&requesterMnemonic, "owner-mnemonic", "",
		"25-word mnemonic of the owner")
	withdrawLostFundsCmd.MarkFlagRequired("owner-mnemonic")
}

var withdrawLostFundsCmd = &cobra.Command{
	Use:   "withdraw-lost-funds",
	Short: "test withdraw lost funds",
	Run: func(cmd *cobra.Command, args []string) {
		err := daemon.TestEnvironmentVariables()
		if err != nil {
			log.Error(err)
			return
		}

		algodClient, err := daemon.InitClients(daemon.AlgodAddress, daemon.AlgodToken)
		if err != nil {
			log.Error(err)
			return
		}
		suggestedParams, err := algodClient.SuggestedParams().Do(context.Background())
		if err != nil {
			log.Error(err)
			return
		}

		ownerSK, err := mnemonic.ToPrivateKey(requesterMnemonic)
		if err != nil {
			log.Error(err)
			return
		}
		sender, err := crypto.GenerateAddressFromSK(ownerSK)
		if err != nil {
			log.Error(err)
			return
		}
		appArgs := [][]byte{
			[]byte("withdraw_lost_funds"),
		}
		appCall, err := future.MakeApplicationNoOpTx(
			appID,
			appArgs,
			nil,
			nil,
			nil,
			suggestedParams,
			sender,
			nil,
			types.Digest{},
			[32]byte{},
			types.ZeroAddress,
		)
		if err != nil {
			log.Error(err)
			return
		}
		appCall.Fee *= 2
		_, stxBytes, err := crypto.SignTransaction(ownerSK, appCall)
		if err != nil {
			log.Error(err)
			return
		}

		txID, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
		if err != nil {
			log.Error(err)
			return
		}
		_, err = waitForTx(algodClient, txID)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("sent %s", txID)
	},
}
