package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"strings"
)

var (
	appID                    uint64
	addressAMnemonic         string
	addressBMnemonic         string
	oraclePKAddressString    string
	oracleOwnerAddressString string
	block                    uint64
)

func init() {
	setLogger()

	queryPhaseCmd.Flags().Uint64Var(&appID, "app-id", 0,
		"Game app ID")
	markFlagRequired(queryPhaseCmd.Flags(), "app-id")

	queryPhaseCmd.Flags().StringVar(&addressAMnemonic, "address-a-mnemonic", "",
		"25-word mnemonic of player A")
	markFlagRequired(queryPhaseCmd.Flags(), "address-a-mnemonic")

	queryPhaseCmd.Flags().StringVar(&addressBMnemonic, "address-b-mnemonic", "",
		"25-word mnemonic of player B")
	markFlagRequired(queryPhaseCmd.Flags(), "address-b-mnemonic")

	queryPhaseCmd.Flags().StringVar(&oraclePKAddressString, "oracle-pk", "",
		"an Algorand address representation of the oracle's PK")
	markFlagRequired(queryPhaseCmd.Flags(), "oracle-pk")

	queryPhaseCmd.Flags().StringVar(&oracleOwnerAddressString, "oracle-owner", "",
		"the oracle owner address")
	markFlagRequired(queryPhaseCmd.Flags(), "oracle-owner")

	queryPhaseCmd.Flags().Uint64Var(&block, "block", 0,
		"the block to take the seed for the VRF input")
	markFlagRequired(queryPhaseCmd.Flags(), "block")
}

func testArguments() (ed25519.PrivateKey, ed25519.PrivateKey, types.Address, types.Address, error) {
	var errors []string
	addressASK, err := mnemonic.ToPrivateKey(addressAMnemonic)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid address-a-mnemonic: %v", err))
	}
	addressBSK, err := mnemonic.ToPrivateKey(addressBMnemonic)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid address-b-mnemonic: %v", err))
	}
	oraclePKAddress, err := types.DecodeAddress(oraclePKAddressString)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid oracle-pk: %v", err))
	}
	oracleOwnerAddress, err := types.DecodeAddress(oracleOwnerAddressString)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid ooracle-owner: %v", err))
	}
	var errResult error
	if errors != nil {
		errResult = fmt.Errorf(strings.Join(errors, ", "))
	}
	return addressASK, addressBSK, oraclePKAddress, oracleOwnerAddress, errResult
}

func privateKeyToAddress(privateKey ed25519.PrivateKey) types.Address {
	var address types.Address
	copy(address[:], privateKey[32:])
	return address
}

func randomHex(n int) (string, []byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", bytes, err
	}
	return hex.EncodeToString(bytes), bytes, nil
}

func computeX(addressA, addressB types.Address, counterBytes []byte) []byte {
	toHash := append(addressA[:], addressB[:]...)
	toHash = append(toHash, counterBytes...)
	hashed := sha256.Sum256(toHash)
	return hashed[:]
}

var queryPhaseCmd = &cobra.Command{
	Use:   "query",
	Short: "test query phase",
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
		addressASK, addressBSK, oraclePKAddress, oracleOwnerAddress, err := testArguments()
		if err != nil {
			log.Error(err)
			return
		}
		randomCounter, randomCounterBytes, err := randomHex(8)
		if err != nil {
			log.Error(err)
			return
		}
		addressA := privateKeyToAddress(addressASK)
		addressB := privateKeyToAddress(addressBSK)
		counter := fmt.Sprintf("0x%s", randomCounter)
		fmt.Printf("counter is: %s\n", counter)
		escrowTealParams := EscrowTealParams{
			AddressA:   addressA,
			AddressB:   addressB,
			CounterHex: counter,
		}
		escrowProgram, err := CompileEscrow(escrowTealParams, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		_, escrowSuffixB64, _ := CutTeal(escrowProgram, 28, 107)
		escrowSuffix, err := base64.StdEncoding.DecodeString(escrowSuffixB64)
		if err != nil {
			log.Error(err)
			return
		}
		escrowAddress := crypto.AddressFromProgram(escrowProgram)
		oraclePKb32 := base32.StdEncoding.EncodeToString(oraclePKAddress[:])
		x := computeX(addressA, addressB, randomCounterBytes)
		oracleTealParams := OracleTealParams{
			AppIDHex:     fmt.Sprintf("0x%016x", appID),
			Arg0:         "vrf",
			Block:        fmt.Sprintf("%08d", block),
			Xb32:         base32.StdEncoding.EncodeToString(x),
			Sender:       escrowAddress,
			SigningPKb32: oraclePKb32,
			OwnerAddr:    oracleOwnerAddress,
		}
		oracleProgram, err := CompileOracle(oracleTealParams, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		oracleEscrowAddress := crypto.AddressFromProgram(oracleProgram)
		fmt.Printf("please fund the escrow %s and the oracle escrow %s accounts and press ENTER\n",
			escrowAddress, oracleEscrowAddress)
		fmt.Scanln()
		aToEscrowTxn, err := future.MakePaymentTxn(
			addressA.String(),
			escrowAddress.String(),
			51000,
			nil,
			"",
			suggestedParams,
		)
		if err != nil {
			log.Error(err)
			return
		}
		bToEscrowTxn, err := future.MakePaymentTxn(
			addressB.String(),
			escrowAddress.String(),
			51000,
			nil,
			"",
			suggestedParams,
		)
		if err != nil {
			log.Error(err)
			return
		}
		appArgs := [][]byte{
			addressA[:],
			addressB[:],
			randomCounterBytes,
			[]byte(fmt.Sprintf("%08d", block)),
			{0},
			escrowSuffix,

		}
		appOptIn, err := future.MakeApplicationOptInTx(
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
		note := []byte("vrf-v0")
		note = append(note, oraclePKAddress[:]...)
		note = append(note, oracleOwnerAddress[:]...)
		note = append(note, escrowAddress[:]...)
		note = append(note, []byte(fmt.Sprintf("%08d", block))...)
		note = append(note, x...)
		note = append(note, []byte(fmt.Sprintf("%08d", appID))...)
		note = append(note, []byte("vrf")...)

		escrowToOracleEscrowTxn, err := future.MakePaymentTxn(
			escrowAddress.String(),
			oracleEscrowAddress.String(),
			50000,
			note,
			"",
			suggestedParams,
		)

		grouped, err := transaction.AssignGroupID(
			[]types.Transaction{aToEscrowTxn, bToEscrowTxn, appOptIn, escrowToOracleEscrowTxn}, "")

		_, signedAToEscrowTxn, err := crypto.SignTransaction(addressASK, grouped[0])
		if err != nil {
			log.Error(err)
			return
		}
		_, signedBToEscrowTxn, err := crypto.SignTransaction(addressBSK, grouped[1])
		if err != nil {
			log.Error(err)
			return
		}
		escrowLogicSig, err := crypto.MakeLogicSig(escrowProgram, [][]byte{[]byte("query")}, nil, crypto.MultisigAccount{})
		_, signedAppOptIn, err := crypto.SignLogicsigTransaction(escrowLogicSig, grouped[2])
		_, signedEscrowToOracleEscrowTxn, err := crypto.SignLogicsigTransaction(escrowLogicSig, grouped[3])

		signedGroup := append(signedAToEscrowTxn, signedBToEscrowTxn...)
		signedGroup = append(signedGroup, signedAppOptIn...)
		signedGroup = append(signedGroup, signedEscrowToOracleEscrowTxn...)

		txID, err := algodClient.SendRawTransaction(signedGroup).Do(context.Background())
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("sent %s", txID)

	},
}

