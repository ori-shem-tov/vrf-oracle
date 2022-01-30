package test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/algorand/go-algorand-sdk/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	appID             uint64
	requesterMnemonic string
	block             uint64
	fee               uint64
)

func init() {
	daemon.SetLogger()

	requestCmd.Flags().Uint64Var(&appID, "app-id", 0,
		"Game app ID")
	requestCmd.MarkFlagRequired("app-id")

	requestCmd.Flags().StringVar(&requesterMnemonic, "requester-mnemonic", "",
		"25-word mnemonic of the requester")
	requestCmd.MarkFlagRequired("requester-mnemonic")

	requestCmd.Flags().Uint64Var(&block, "block", 0,
		"the block to take the seed for the VRF input")
	requestCmd.MarkFlagRequired("block")
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

	optinCall, err := future.MakeApplicationOptInTx(
		appID,
		nil,
		nil,
		nil,
		nil,
		suggestedParams,
		requesterAddr,
		nil,
		types.Digest{},
		[32]byte{},
		types.ZeroAddress,
	)

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
		[]types.Transaction{optinCall, paymentTxn, appCall}, "")

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

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "test VRF request",
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

		feeStateValue, ok := GetFromState([]byte("service_fee"), appObject.Params.GlobalState)
		if !ok {
			log.Errorf("app %d doesn't have \"service_fee\" key", appID)
			return
		}
		requesterAddr, err := crypto.GenerateAddressFromSK(requesterSK)
		if err != nil {
			log.Error(err)
			return
		}
		for j := 0; j < 5; j++ {
			accounts := make([]crypto.Account, 1000)
			var signedPayments []byte
			var signedRequests []byte
			for i := 0; i < len(accounts); i++ {
				accounts[i] = crypto.GenerateAccount()
				payment, err := future.MakePaymentTxn(requesterAddr.String(), accounts[i].Address.String(), 1000000, nil, "", suggestedParams)
				if err != nil {
					log.Error(err)
					return
				}
				_, signedPayment, err := crypto.SignTransaction(requesterSK, payment)
				if err != nil {
					log.Error(err)
					return
				}
				signedPayments = append(signedPayments, signedPayment...)

				signedGroup, err := generateRequestTxnGroup(accounts[i].PrivateKey, appEscrow, suggestedParams, feeStateValue.Uint, block, appID)
				signedRequests = append(signedRequests, signedGroup...)
			}
			err = ioutil.WriteFile(fmt.Sprintf("large-pays%d.stx", j), signedPayments, os.ModePerm)
			if err != nil {
				log.Error(err)
				return
			}
			err = ioutil.WriteFile(fmt.Sprintf("large-reqs%d.stx", j), signedRequests, os.ModePerm)
			if err != nil {
				log.Error(err)
				return
			}
		}

		//signedGroup, err := generateRequestTxnGroup(requesterSK, appEscrow, suggestedParams, feeStateValue.Uint, block, appID)
		//
		//txID, err := algodClient.SendRawTransaction(signedGroup).Do(context.Background())
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//_, err = waitForTx(algodClient, txID)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//log.Infof("sent %s", txID)

	},
}

func GetFromState(key []byte, state []models.TealKeyValue) (models.TealValue, bool) {
	kB64 := base64.StdEncoding.EncodeToString(key)
	for _, kv := range state {
		if kv.Key == kB64 {
			return kv.Value, true
		}
	}
	return models.TealValue{}, false
}
