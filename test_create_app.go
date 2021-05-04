package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	appCreatorMnemonic         string
)

func init() {
	setLogger()

	createAppCmd.Flags().StringVar(&appCreatorMnemonic, "app-creator-mnemonic", "", "25-word mnemonic of the app creator")
	markFlagRequired(createAppCmd.Flags(), "app-creator-mnemonic")

	createAppCmd.Flags().StringVar(&oraclePKAddressString, "oracle-pk", "",
		"an Algorand address representation of the oracle's PK")
	markFlagRequired(createAppCmd.Flags(), "oracle-pk")

	createAppCmd.Flags().StringVar(&oracleOwnerAddressString, "oracle-owner", "",
		"the oracle owner address")
	markFlagRequired(createAppCmd.Flags(), "oracle-owner")


}

func createGameApp(appCreatorSK ed25519.PrivateKey, oraclePKAddress, oracleOwnerAddress types.Address,
	algoClient *algod.Client, suggestedParams types.SuggestedParams) (string, error) {
	appCreatorAddress := privateKeyToAddress(appCreatorSK)
	oraclePrefix, _, oracleSuffixHash, err := cutOracle(algoClient)
	if err != nil {
		return "", fmt.Errorf("failed cutting oracle TEAL: %v", err)
	}
	escrowPrefix, _, escrowSuffixHash, err := cutEscrow(algoClient)
	if err != nil {
		return "", fmt.Errorf("failed cutting escrow TEAL: %v", err)
	}
	oracleSigningPKB32 := base32.StdEncoding.EncodeToString(oraclePKAddress[:])
	statefulGameTealParams := StatefulGameTealParams{
		GameEscrowPrefixB64:       escrowPrefix,
		GameEscrowSuffixHashB64:   escrowSuffixHash,
		OracleSigningPKB32:        oracleSigningPKB32,
		OracleOwnerAddress:        oracleOwnerAddress,
		OracleEscrowPrefixB64:     oraclePrefix,
		OracleEscrowSuffixHashB64: oracleSuffixHash,
	}
	approval, err := CompileStatefulGame(statefulGameTealParams, algoClient)
	if err != nil {
		return "", fmt.Errorf("failed compiling statful TEAL: %v", err)
	}
	localStateSchema := types.StateSchema{
		NumUint:      0,
		NumByteSlice: 6,
	}
	tx, err := future.MakeApplicationCreateTx(
		false,
		approval,
		StatefulGameClear,
		types.StateSchema{},
		localStateSchema,
		nil,
		nil,
		nil,
		nil,
		suggestedParams,
		appCreatorAddress,
		nil,
		types.Digest{},
		[32]byte{},
		types.Address{},
	)
	if err != nil {
		return "", fmt.Errorf("failed creating app call: %v", err)
	}
	_, stxBytes, err := crypto.SignTransaction(appCreatorSK, tx)
	if err != nil {
		return "", fmt.Errorf("failed signing app call: %v", err)
	}
	txID, err := algoClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed sending app call: %v", err)
	}
	return txID, nil
}

func cutOracle(algodClient *algod.Client) (string, string, string, error) {
	oracleTealParams := OracleTealParams{
		AppIDHex:     "0x1234567812345678",
		Arg0:         "vrf",
		Block:        "11111111",
		Xb32:         "CQQOAKRGOMQAHWWV7RS23345OFAUBPNMV2SIDQ3WFQ2RGA6T3KCQ====",
		Sender:       types.Address([32]byte{1, 2, 3, 4, 5, 6}),
		SigningPKb32: "YUO5WDTSKVI5VADGDNGDCFDTPDO2TQMH2OZGZ6MLDXA6G2ZU5CDQ====",
		OwnerAddr:    types.Address([32]byte{6, 5, 4, 3, 2, 1}),
	}
	program, err := CompileOracle(oracleTealParams, algodClient)
	if err != nil {
		return "", "", "", err
	}
	prefix, suffix, suffixHash := CutTeal(program, 9, 163)
	return prefix, suffix, suffixHash, nil
}

func cutEscrow(algodClient *algod.Client) (string, string, string, error) {
	escrowTealParams := EscrowTealParams{
		AddressA:   types.Address([32]byte{1, 2, 3, 4, 5, 6}),
		AddressB:   types.Address([32]byte{6, 5, 4, 3, 2, 1}),
		CounterHex: "0x1234567812345678",
	}
	program, err := CompileEscrow(escrowTealParams, algodClient)
	if err != nil {
		return "", "", "", err
	}
	prefix, suffix, suffixHash := CutTeal(program, 28, 107)
	return prefix, suffix, suffixHash, nil
}

var createAppCmd = &cobra.Command{
	Use:   "create-app",
	Short: "create the game app",
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
		appCreatorSK, err := mnemonic.ToPrivateKey(appCreatorMnemonic)
		if err != nil {
			log.Error(err)
			return
		}
		oraclePKAddress, err := types.DecodeAddress(oraclePKAddressString)
		if err != nil {
			log.Error(err)
			return
		}
		oracleOwnerAddress, err := types.DecodeAddress(oracleOwnerAddressString)
		if err != nil {
			log.Error(err)
			return
		}
		suggestedParams, err := algodClient.SuggestedParams().Do(context.Background())
		if err != nil {
			log.Error(err)
			return
		}

		txID, err := createGameApp(appCreatorSK, oraclePKAddress, oracleOwnerAddress, algodClient, suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		var res models.PendingTransactionInfoResponse
		err = Retry(1, 5,
			func() error {
				var err error
				res, _, err = algodClient.PendingTransactionInformation(txID).Do(context.Background())
				if err == nil && (res.ConfirmedRound == 0 || res.PoolError != "") {
					return fmt.Errorf("ConfirmedRound: %d, PoolError: %s", res.ConfirmedRound, res.PoolError)
				}
				return err
			},
			func(err error) {
				log.Warnf("failed getting pending transaction info from algod, trying again...: %v", err)
			},
		)
		if err != nil {
			log.Error(err)
			return
		}
		fmt.Printf("app id: %d\n", res.ApplicationIndex)
	},
}


