package test

import (
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	"github.com/ori-shem-tov/vrf-oracle/teal/compile"
	"github.com/ori-shem-tov/vrf-oracle/teal/tealtools"
	"github.com/ori-shem-tov/vrf-oracle/teal/templates"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	appCreatorMnemonic         string
)

func init() {
	daemon.SetLogger()

	createAppCmd.Flags().StringVar(&appCreatorMnemonic, "app-creator-mnemonic", "", "25-word mnemonic of the app creator")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "app-creator-mnemonic")

	createAppCmd.Flags().StringVar(&oraclePKAddressString, "oracle-pk", "",
		"an Algorand address representation of the oracle's PK")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "oracle-pk")

	createAppCmd.Flags().StringVar(&oracleOwnerAddressString, "oracle-owner", "",
		"the oracle owner address")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "oracle-owner")


}

func createGameApp(appCreatorSK ed25519.PrivateKey, oraclePKAddress, oracleOwnerAddress types.Address,
	algodClient *algod.Client, suggestedParams types.SuggestedParams) (uint64, error) {
	appCreatorAddress := privateKeyToAddress(appCreatorSK)
	oraclePrefix, _, oracleSuffixHash, err := cutOracle(algodClient)
	if err != nil {
		return 0, fmt.Errorf("failed cutting oracle TEAL: %v", err)
	}
	escrowPrefix, _, escrowSuffixHash, err := cutEscrow(algodClient)
	if err != nil {
		return 0, fmt.Errorf("failed cutting escrow TEAL: %v", err)
	}
	oracleSigningPKB32 := base32.StdEncoding.EncodeToString(oraclePKAddress[:])
	statefulGameTealParams := compile.StatefulGameTealParams{
		GameEscrowPrefixB64:       escrowPrefix,
		GameEscrowSuffixHashB64:   escrowSuffixHash,
		OracleSigningPKB32:        oracleSigningPKB32,
		OracleOwnerAddress:        oracleOwnerAddress,
		OracleEscrowPrefixB64:     oraclePrefix,
		OracleEscrowSuffixHashB64: oracleSuffixHash,
	}
	approval, err := compile.CompileStatefulGame(statefulGameTealParams, algodClient)
	if err != nil {
		return 0, fmt.Errorf("failed compiling statful TEAL: %v", err)
	}
	localStateSchema := types.StateSchema{
		NumUint:      0,
		NumByteSlice: 6,
	}
	tx, err := future.MakeApplicationCreateTx(
		false,
		approval,
		templates.StatefulGameClear,
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
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("failed creating app call: %v", err)
	}
	_, stxBytes, err := crypto.SignTransaction(appCreatorSK, tx)
	if err != nil {
		return 0, fmt.Errorf("failed signing app call: %v", err)
	}
	txID, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed sending app call: %v", err)
	}
	res, err := waitForTx(algodClient, txID)
	if err != nil {
		return 0, err
	}

	return res.ApplicationIndex, nil
}

func cutOracle(algodClient *algod.Client) (string, string, string, error) {
	oracleTealParams := compile.OracleTealParams{
		AppIDHex:     "0x1234567812345678",
		Arg0:         "vrf",
		Block:        "11111111",
		Xb32:         "CQQOAKRGOMQAHWWV7RS23345OFAUBPNMV2SIDQ3WFQ2RGA6T3KCQ====",
		Sender:       types.Address([32]byte{1, 2, 3, 4, 5, 6}),
		SigningPKb32: "YUO5WDTSKVI5VADGDNGDCFDTPDO2TQMH2OZGZ6MLDXA6G2ZU5CDQ====",
		OwnerAddr:    types.Address([32]byte{6, 5, 4, 3, 2, 1}),
	}
	program, err := compile.CompileOracle(oracleTealParams, algodClient)
	if err != nil {
		return "", "", "", err
	}
	prefix, suffix, suffixHash := tealtools.CutTeal(program, 9, 163)
	return prefix, suffix, suffixHash, nil
}

func cutEscrow(algodClient *algod.Client) (string, string, string, error) {
	escrowTealParams := compile.EscrowTealParams{
		AddressA:   types.Address([32]byte{1, 2, 3, 4, 5, 6}),
		AddressB:   types.Address([32]byte{6, 5, 4, 3, 2, 1}),
		CounterHex: "0x1234567812345678",
	}
	program, err := compile.CompileEscrow(escrowTealParams, algodClient)
	if err != nil {
		return "", "", "", err
	}
	prefix, suffix, suffixHash := tealtools.CutTeal(program, 28, 107)
	return prefix, suffix, suffixHash, nil
}

var createAppCmd = &cobra.Command{
	Use:   "create-app",
	Short: "create the game app",
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
		appCreatorSK, err := mnemonic.ToPrivateKey(appCreatorMnemonic)
		if err != nil {
			log.Error(err)
			return
		}
		oraclePKAddress, oracleOwnerAddress, err := decodeOracleAddresses(oraclePKAddressString,
			oracleOwnerAddressString)
		if err != nil {
			log.Error(err)
			return
		}
		suggestedParams, err := algodClient.SuggestedParams().Do(context.Background())
		if err != nil {
			log.Error(err)
			return
		}

		appID, err := createGameApp(appCreatorSK, oraclePKAddress, oracleOwnerAddress, algodClient, suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		fmt.Printf("app id: %d\n", appID)
	},
}


