package test

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	"github.com/ori-shem-tov/vrf-oracle/teal/compile"
	"github.com/ori-shem-tov/vrf-oracle/teal/tealtools"
	"github.com/ori-shem-tov/vrf-oracle/tools"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	oraclePKAddressString string
	oracleOwnerAddressString string
)

func init() {
	daemon.SetLogger()
	
	EndToEndCmd.Flags().StringVar(&oraclePKAddressString, "oracle-pk", "",
		"an Algorand address representation of the oracle's PK")
	daemon.MarkFlagRequired(EndToEndCmd.Flags(), "oracle-pk")

	EndToEndCmd.Flags().StringVar(&oracleOwnerAddressString, "oracle-owner", "",
		"the oracle owner address")
	daemon.MarkFlagRequired(EndToEndCmd.Flags(), "oracle-owner")
}

const (
	requiredFundingAlgosPerAccount = 10
	requiredFundingAlgos = 5 * requiredFundingAlgosPerAccount + 1
)

func waitForTx(algodClient *algod.Client, txID string) (models.PendingTransactionInfoResponse, error) {
	var res models.PendingTransactionInfoResponse
	err := tools.Retry(1, 5,
		func() error {
			var err error
			res, _, err = algodClient.PendingTransactionInformation(txID).Do(context.Background())
			if err == nil && (res.ConfirmedRound == 0 || res.PoolError != "") {
				return fmt.Errorf("still pending ConfirmedRound: %d, PoolError: %s",
					res.ConfirmedRound, res.PoolError)
			}
			return err
		},
		func(err error) {
			log.Debugf("%v, trying again...", err)
		},
	)
	return res, err
}

func pay(algodClient *algod.Client, from crypto.Account, to types.Address, amount uint64,
	sp types.SuggestedParams) (models.PendingTransactionInfoResponse, error) {
	var res models.PendingTransactionInfoResponse
	paymentTxn, err := future.MakePaymentTxn(
		from.Address.String(), to.String(), amount, nil, "", sp)
	if err != nil {
		return res, fmt.Errorf("failed generating transaction of %d from %s to %s: %v", amount, from.Address, to, err)
	}
	_, stxBytes, err := crypto.SignTransaction(from.PrivateKey, paymentTxn)
	if err != nil {
		return res, fmt.Errorf("failed signing transaction of %d from %s to %s: %v", amount, from.Address, to, err)
	}
	txID, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return res, fmt.Errorf("failed sending transaction of %d from %s to %s: %v", amount, from.Address, to, err)
	}
	res, err = waitForTx(algodClient, txID)
	return res, err
}

func generateAndFundFundingAccount() (crypto.Account, error) {
	fundingAccount := crypto.GenerateAccount()
	fmt.Printf("please send %d Algos to the funding account @ %s and press ENTER\n", requiredFundingAlgos,
		fundingAccount.Address)
	_, err := fmt.Scanln()
	return fundingAccount, err
}

func generateAndFundAccounts(fundingAccount crypto.Account, algodClient *algod.Client, params types.SuggestedParams) (
	crypto.Account, crypto.Account, crypto.Account, error) {
	paymentPerAccount := uint64(types.ToMicroAlgos(requiredFundingAlgosPerAccount))

	appCreator := crypto.GenerateAccount()
	fmt.Printf("generated app creator address %s\n", appCreator.Address)

	_, err := pay(algodClient, fundingAccount, appCreator.Address, paymentPerAccount, params)
	if err != nil {
		return crypto.Account{}, crypto.Account{}, crypto.Account{}, err
	}
	A := crypto.GenerateAccount()
	fmt.Printf("generated A address %s\n", A.Address)
	_, err = pay(algodClient, fundingAccount, A.Address, paymentPerAccount, params)
	if err != nil {
		return crypto.Account{}, crypto.Account{}, crypto.Account{}, err
	}
	B := crypto.GenerateAccount()
	fmt.Printf("generated B address %s\n", B.Address)
	_, err = pay(algodClient, fundingAccount, B.Address, paymentPerAccount, params)
	if err != nil {
		return crypto.Account{}, crypto.Account{}, crypto.Account{}, err
	}
	return appCreator, A, B, nil
}

func decodeOracleAddresses(oraclePKAddressString, oracleOwnerAddressString string) (types.Address, types.Address,
	error) {
	oraclePKAddress, err := types.DecodeAddress(oraclePKAddressString)
	if err != nil {
		return types.Address{}, types.Address{}, err
	}
	oracleOwnerAddress, err := types.DecodeAddress(oracleOwnerAddressString)
	if err != nil {
		return types.Address{}, types.Address{}, err
	}
	return oraclePKAddress, oracleOwnerAddress, nil
}

func generateGameEscrow(algodClient *algod.Client, addressA, addressB types.Address, randomCounter string) ([]byte, []byte,
	types.Address, error) {
	escrowTealParams := compile.EscrowTealParams{
		AddressA:   addressA,
		AddressB:   addressB,
		CounterHex: randomCounter,
	}
	escrowProgram, err := compile.CompileEscrow(escrowTealParams, algodClient)
	if err != nil {
		return nil, nil, types.Address{}, err
	}
	_, escrowSuffixB64, _ := tealtools.CutTeal(escrowProgram, 28, 107)
	escrowSuffix, err := base64.StdEncoding.DecodeString(escrowSuffixB64)
	if err != nil {
		return nil, nil, types.Address{}, err
	}
	escrowAddress := crypto.AddressFromProgram(escrowProgram)
	return escrowProgram, escrowSuffix, escrowAddress, nil
}

var EndToEndCmd = &cobra.Command{
	Use:   "e2e",
	Short: "end-to-end test",
	Run: func(cmd *cobra.Command, args []string) {
		//err := daemon.TestEnvironmentVariables()
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//algodClient, _, err := daemon.InitClients(daemon.AlgodAddress, daemon.AlgodToken, daemon.IndexerAddress, daemon.IndexerToken)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//fundingAccount, err := generateAndFundFundingAccount()
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//suggestedParams, err := algodClient.SuggestedParams().Do(context.Background())
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//
		//appCreator, A, B, err := generateAndFundAccounts(fundingAccount, algodClient, suggestedParams)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//
		//oraclePKAddress, oracleOwnerAddress, err := decodeOracleAddresses(oraclePKAddressString,
		//	oracleOwnerAddressString)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//
		//appID, err := createGameApp(appCreator.PrivateKey, oraclePKAddress, oracleOwnerAddress, algodClient,
		//	suggestedParams)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//fmt.Printf("app id: %d\n", appID)
		//
		//randomCounter, randomCounterBytes, err := randomHex(8)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//fmt.Printf("counter is: %s\n", randomCounter)
		//
		//addressA := A.Address
		//addressB := B.Address
		//escrowProgram, escrowSuffix, escrowAddress, err := generateGameEscrow(algodClient, addressA, addressB,
		//	randomCounter)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//res, err := pay(algodClient, fundingAccount, escrowAddress, 10000000, suggestedParams)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//block := res.ConfirmedRound + 10
		//fmt.Printf("block %d\n", block)
		//oraclePKb32 := base32.StdEncoding.EncodeToString(oraclePKAddress[:])
		//x := computeX(addressA, addressB, randomCounterBytes)
		//oracleTealParams := compile.OracleTealParams{
		//	AppIDHex:     fmt.Sprintf("0x%016x", appID),
		//	Arg0:         "vrf",
		//	Block:        fmt.Sprintf("%08d", block),
		//	Xb32:         base32.StdEncoding.EncodeToString(x),
		//	Sender:       escrowAddress,
		//	SigningPKb32: oraclePKb32,
		//	OwnerAddr:    oracleOwnerAddress,
		//}
		//oracleProgram, err := compile.CompileOracle(oracleTealParams, algodClient)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//oracleEscrowAddress := crypto.AddressFromProgram(oracleProgram)
		//
		//_, err = pay(algodClient, fundingAccount, oracleEscrowAddress, 10000000, suggestedParams)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//
		//aToEscrowTxn, err := future.MakePaymentTxn(
		//	addressA.String(),
		//	escrowAddress.String(),
		//	51000,
		//	nil,
		//	"",
		//	suggestedParams,
		//)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//bToEscrowTxn, err := future.MakePaymentTxn(
		//	addressB.String(),
		//	escrowAddress.String(),
		//	51000,
		//	nil,
		//	"",
		//	suggestedParams,
		//)
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//appArgs := [][]byte{
		//	addressA[:],
		//	addressB[:],
		//	randomCounterBytes,
		//	[]byte(fmt.Sprintf("%08d", block)),
		//	{0},
		//	escrowSuffix,
		//
		//}
		//appOptIn, err := future.MakeApplicationOptInTx(
		//	appID,
		//	appArgs,
		//	nil,
		//	nil,
		//	nil,
		//	suggestedParams,
		//	escrowAddress,
		//	nil,
		//	types.Digest{},
		//	[32]byte{},
		//	types.Address{},
		//)
		//note := []byte("vrf-v0")
		//note = append(note, oraclePKAddress[:]...)
		//note = append(note, oracleOwnerAddress[:]...)
		//note = append(note, escrowAddress[:]...)
		//note = append(note, []byte(fmt.Sprintf("%08d", block))...)
		//note = append(note, x...)
		//note = append(note, []byte(fmt.Sprintf("%08d", appID))...)
		//note = append(note, []byte("vrf")...)
		//
		//escrowToOracleEscrowTxn, err := future.MakePaymentTxn(
		//	escrowAddress.String(),
		//	oracleEscrowAddress.String(),
		//	50000,
		//	note,
		//	"",
		//	suggestedParams,
		//)
		//
		//grouped, err := transaction.AssignGroupID(
		//	[]types.Transaction{aToEscrowTxn, bToEscrowTxn, appOptIn, escrowToOracleEscrowTxn}, "")
		//
		//_, signedAToEscrowTxn, err := crypto.SignTransaction(A.PrivateKey, grouped[0])
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//_, signedBToEscrowTxn, err := crypto.SignTransaction(B.PrivateKey, grouped[1])
		//if err != nil {
		//	log.Error(err)
		//	return
		//}
		//escrowLogicSig, err := crypto.MakeLogicSig(escrowProgram, [][]byte{[]byte("query")}, nil, crypto.MultisigAccount{})
		//_, signedAppOptIn, err := crypto.SignLogicsigTransaction(escrowLogicSig, grouped[2])
		//_, signedEscrowToOracleEscrowTxn, err := crypto.SignLogicsigTransaction(escrowLogicSig, grouped[3])
		//
		//signedGroup := append(signedAToEscrowTxn, signedBToEscrowTxn...)
		//signedGroup = append(signedGroup, signedAppOptIn...)
		//signedGroup = append(signedGroup, signedEscrowToOracleEscrowTxn...)
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
