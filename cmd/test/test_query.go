package test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"strings"
)

var (
	appID                    uint64
	requesterMnemonic		 string
	block                    uint64
	fee						 uint64
)

func init() {
	daemon.SetLogger()

	queryPhaseCmd.Flags().Uint64Var(&appID, "app-id", 0,
		"Game app ID")
	daemon.MarkFlagRequired(queryPhaseCmd.Flags(), "app-id")

	queryPhaseCmd.Flags().StringVar(&requesterMnemonic, "requester-mnemonic", "",
		"25-word mnemonic of the requester")
	daemon.MarkFlagRequired(queryPhaseCmd.Flags(), "requester-mnemonic")

	queryPhaseCmd.Flags().Uint64Var(&block, "block", 0,
		"the block to take the seed for the VRF input")
	daemon.MarkFlagRequired(queryPhaseCmd.Flags(), "block")
}

func testRequestArguments() (ed25519.PrivateKey, types.Address, error) {
	var errors []string
	requesterSK, err := mnemonic.ToPrivateKey(requesterMnemonic)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid requester-mnemonic: %v", err))
	}
	appEscrow := crypto.GetApplicationAddress(appID)
	var errResult error
	if errors != nil {
		errResult = fmt.Errorf(strings.Join(errors, ", "))
	}
	return requesterSK, appEscrow, errResult
}

func randomHex(n int) (string, []byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", bytes, err
	}
	return fmt.Sprintf("0x%s", hex.EncodeToString(bytes)), bytes, nil
}

func generateRequestTxnGroup(requesterSK ed25519.PrivateKey, appEscrow types.Address, suggestedParams types.SuggestedParams, fee, block, appID uint64) ([]byte, error) {
	_, randomCounterBytes, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	requesterAddr, err := crypto.GenerateAddressFromSK(requesterSK)
	if err != nil {
		return nil, err
	}

	paymentTxn, err := future.MakePaymentTxn(
		requesterAddr.String(),
		appEscrow.String(),
		fee,
		nil,
		"",
		suggestedParams,
	)
	if err != nil {
		return nil, err
	}
	blockBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockBytes, block)
	appArgs := [][]byte{
		[]byte("request"),
		blockBytes,
		randomCounterBytes,
	}

	appCall, err := future.MakeApplicationNoOpTx(
		appID,
		appArgs,
		nil,
		nil,
		nil,
		suggestedParams,
		requesterAddr,
		nil,
		types.Digest{},
		[32]byte{},
		types.Address{},
	)

	grouped, err := transaction.AssignGroupID(
		[]types.Transaction{paymentTxn, appCall}, "")

	if err != nil {
		return nil, err
	}

	var signedGroup []byte
	for _, txn := range grouped {
		_, signed, err := crypto.SignTransaction(requesterSK, txn)
		if err != nil {
			return nil, fmt.Errorf("failed signing app call: %v", err)
		}
		signedGroup = append(signedGroup, signed...)
	}

	return signedGroup, nil
}

var queryPhaseCmd = &cobra.Command{
	Use:   "query",
	Short: "test query phase",
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
		requesterSK, appEscrow, err := testRequestArguments()
		if err != nil {
			log.Error(err)
			return
		}

		appObject, err := algodClient.GetApplicationByID(appID).Do(context.Background())
		if err != nil {
			log.Error(err)
			return
		}

		feeStateValue, ok := daemon.GetFromState([]byte("service_fee"), appObject.Params.GlobalState)
		if !ok {
			log.Errorf("app %d doesn't have \"service_fee\" key", appID)
			return
		}

		signedGroup, err := generateRequestTxnGroup(requesterSK, appEscrow, suggestedParams, feeStateValue.Uint, block, appID)

		txID, err := algodClient.SendRawTransaction(signedGroup).Do(context.Background())
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

