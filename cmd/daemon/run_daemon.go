package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/abi"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/libsodiumwrapper"
	"github.com/ori-shem-tov/vrf-oracle/tools"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type Result struct {
	Round    uint64
	UserData []byte
	Method   string
}

var (
	approvalProgramFilename  string
	clearProgramFilename     string
	dummyAppApprovalFilename string
	dummyAppClearFilename    string
	vrfMnemonicString        string // mnemonic for generating the vrf
	serviceMnemonicString    string // mnemonic for the service account (used to send responses to the smart-contract)
	startingRound            uint64 // the round from which the daemon starts scanning
	AlgodAddress             = os.Getenv("AF_ALGOD_ADDRESS")
	AlgodToken               = os.Getenv("AF_ALGOD_TOKEN")
	logLevelEnv              = strings.ToLower(os.Getenv("VRF_LOG_LEVEL"))
	vrfOutputsHistory        map[uint64][]byte // stores the history of the VRF outputs that were generated
	resultsHistory           map[string]Result // stores the 'get' and 'must_get' results history from tests
)

const (
	WaitBetweenBlocksMS = 1
	NumOfDummyTxns      = 9

	// See ./DESIGN.md for definition of indexes, slots, and cells
	NbVrfSlots         = 63 // number of slots used to store VRF outputs
	NbVrfCellsPerSlot  = 3
	NbStoredVrfOutputs = NbVrfSlots * NbVrfCellsPerSlot // this is also the number of indexes

	VrfRoundMultiple = 8 // we only store VRF outputs for rounds that are multiple of this number

	// Lengths of the various VRF associated values
	VrfProofLen        = 80
	StoredVrfOutputLen = 32 // length of the stored VRF output (that are truncated)

	// This part is for the recovery parameters
	// In case no VRF proof was submitted for too long, there will be a gap
	// in the rounds for which random outputs can be provided
	// To get this gap as small as possible, the VRF proof submitter
	// is required to submit a VRF proof as old as possible, minus the grace period
	// which means submitted round <= current round - NbRetainedBlocks + NbGraceBlocks
	NbRetainedBlocks = 1000
	NbGraceBlocks    = 2 * VrfRoundMultiple
)

func init() {
	tools.SetLogger(logLevelEnv)

	RunDaemonCmd.Flags().StringVar(&vrfMnemonicString, "vrf-mnemonic", "",
		"25-word mnemonic of the oracle for computing vrf (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "vrf-mnemonic")

	RunDaemonCmd.Flags().StringVar(&serviceMnemonicString, "service-mnemonic", "",
		"25-word mnemonic of the service for writing the response (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "service-mnemonic")

	RunDaemonCmd.Flags().Uint64Var(&startingRound, "starting-round", 0,
		"the round to start scanning from (optional. default: current round)")

	RunDaemonCmd.Flags().StringVar(&approvalProgramFilename, "approval-program", "",
		"TEAL script of the approval program (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "approval-program")

	RunDaemonCmd.Flags().StringVar(&clearProgramFilename, "clear-program", "",
		"TEAL script of the clear program (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "clear-program")

	RunDaemonCmd.Flags().StringVar(&dummyAppApprovalFilename, "dummy-app-approval", "",
		"TEAL script of the dummy app approval (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "dummy-app-approval")

	RunDaemonCmd.Flags().StringVar(&dummyAppClearFilename, "dummy-app-clear", "",
		"TEAL script of the dummy app clear (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "dummy-app-clear")

}

// buildSubmitTransactionGroupABI builds a transaction group to submit the VRF proof to the beacon's smart contract.
// The first transaction in the group is the actual application call submitting the proof and the rest NumOfDummyTxns
// are used for cost pool increase.
func buildSubmitTransactionGroupABI(appID, dummyAppID, round uint64, serviceAccount crypto.Account,
	vrfProof []byte, sp types.SuggestedParams) ([]byte, error) {

	var atc future.AtomicTransactionComposer
	signer := future.BasicAccountTransactionSigner{Account: serviceAccount}
	methodSig := "submit(uint64,byte[80])void"
	method, err := abi.MethodFromSignature(methodSig)
	if err != nil {
		return nil, fmt.Errorf("error abi.MethodFromSignature(methodSig) %v", err)
	}
	var vrfProofArray [VrfProofLen]byte
	copy(vrfProofArray[:], vrfProof)
	methodCallParams := future.AddMethodCallParams{
		AppID:           appID,
		Method:          method,
		MethodArgs:      []interface{}{round, vrfProofArray},
		Sender:          serviceAccount.Address,
		SuggestedParams: sp,
		Signer:          signer,
	}
	err = atc.AddMethodCall(methodCallParams)
	if err != nil {
		return nil, fmt.Errorf("error atc.AddMethodCall(methodCallParams) %v", err)
	}

	for i := 0; i < NumOfDummyTxns; i++ {
		dummyAppCall, err := future.MakeApplicationNoOpTx(
			dummyAppID,
			nil,
			nil,
			nil,
			nil,
			sp,
			serviceAccount.Address,
			[]byte{byte(i)},
			types.Digest{},
			[32]byte{},
			types.ZeroAddress,
		)
		if err != nil {
			return nil, fmt.Errorf("failed creating dummy app call: %v", err)
		}
		err = atc.AddTransaction(future.TransactionWithSigner{
			Txn:    dummyAppCall,
			Signer: signer,
		})
		if err != nil {
			return nil, fmt.Errorf("error atc.AddTransaction(future.TransactionWithSigner{ %v", err)
		}
	}
	stxsSlice, err := atc.GatherSignatures()
	if err != nil {
		return nil, fmt.Errorf("error in atc.GatherSignatures: %w", err)
	}
	var stxBytes []byte
	for _, stx := range stxsSlice {
		stxBytes = append(stxBytes, stx...)
	}
	return stxBytes, nil
}

// getVrfPrivateKey converts ed25519.PrivateKey ([]byte) to libsodium_wrapper.VrfPrivkey ([64]byte)
func getVrfPrivateKey(key ed25519.PrivateKey) libsodiumwrapper.VrfPrivkey {
	var vrfPrivateKey libsodiumwrapper.VrfPrivkey
	copy(vrfPrivateKey[:], key)
	return vrfPrivateKey
}

// buildVrfInput concats the block number with the block seed and hash it to create the input to the VRF
func buildVrfInput(blockNumber, blockSeed []byte) [sha512.Size256]byte {
	toHash := append(blockNumber, blockSeed...)
	return sha512.Sum512_256(toHash)
}

// computeAndSignVrf computes the VRF proof and returns the VRF output and the VRF proof (to be verified by the smart
// contract)
func computeAndSignVrf(blockNumber, blockSeed []byte, oracleVrfKey ed25519.PrivateKey) ([]byte, []byte, error) {
	vrfInput := buildVrfInput(blockNumber, blockSeed)
	vrfPrivateKey := getVrfPrivateKey(oracleVrfKey)
	proof, ok := vrfPrivateKey.ProveBytes(vrfInput[:])
	if !ok {
		return nil, nil, fmt.Errorf("error computing vrf proof")
	}
	vrfOutput, ok := proof.Hash()
	if !ok {
		return nil, nil, fmt.Errorf("error computing vrf output")
	}
	return vrfOutput[:], proof[:], nil
}

// handleCurrentRound computes the VRF proof for a given round and submits it to the beacon's smart contract for
// verification
func handleCurrentRound(currentRoundHandled uint64, vrfPrivateKey ed25519.PrivateKey, serviceAccount crypto.Account,
	appID, dummyAppID uint64, algodClient *algod.Client, suggestedParams types.SuggestedParams, blockSeed []byte,
) error {
	blockNumberBytes := convertUint64ToBigEndianBytes(currentRoundHandled)
	vrfOutput, vrfProof, err := computeAndSignVrf(
		blockNumberBytes,
		blockSeed,
		vrfPrivateKey,
	)
	if err != nil {
		return fmt.Errorf("failed computing vrf for %d: %v", currentRoundHandled, err)
	}

	stxBytes, err := buildSubmitTransactionGroupABI(
		appID,
		dummyAppID,
		currentRoundHandled,
		serviceAccount,
		vrfProof,
		suggestedParams,
	)
	if err != nil {
		return fmt.Errorf(
			"failed building transactions group for %d: %v",
			currentRoundHandled,
			err,
		)
	}
	txID, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return fmt.Errorf(
			"failed sending transactions group for %d: %v",
			currentRoundHandled,
			err,
		)
		//log.Debugf("stxbytes bas64: %v", base64.StdEncoding.EncodeToString(stxBytes))
	}
	vrfOutputsHistory[currentRoundHandled] = vrfOutput
	log.Infof("Sent transaction %s\n########################################################", txID)
	return nil
}

// GetSuggestedParams gets suggested params with exponential back-off
func GetSuggestedParams(algodClient *algod.Client) (types.SuggestedParams, error) {
	var sp types.SuggestedParams
	err := tools.Retry(1, 5,
		func() error {
			var err error
			sp, err = algodClient.SuggestedParams().Do(context.Background())
			return err
		},
		func(err error) {
			log.Warnf("failed getting suggested params from algod, trying again...: %v", err)
		},
	)
	return sp, err
}

// getBlock gets a block with exponential back-off
func getBlock(algodClient *algod.Client, round uint64) (types.Block, error) {
	var block types.Block
	err := tools.Retry(1, 5,
		func() error {
			var err error
			block, err = algodClient.Block(round).Do(context.Background())
			return err
		},
		func(err error) {
			log.Warnf("can't retrieve block %d, trying again...: %v", round, err)
		},
	)
	return block, err
}

// sendDummyTxn sends a 0 amount self transactions
func sendDummyTxn(algodClient *algod.Client, account crypto.Account, suggestedParams types.SuggestedParams) {
	note := make([]byte, 32)
	crypto.RandomBytes(note)
	txn, err := future.MakePaymentTxn(
		account.Address.String(),
		account.Address.String(),
		0,
		note,
		"",
		suggestedParams,
	)
	if err != nil {
		panic(err)
	}
	_, stx, err := crypto.SignTransaction(account.PrivateKey, txn)
	if err != nil {
		panic(err)
	}
	_, err = algodClient.SendRawTransaction(stx).Do(context.Background())
	if err != nil {
		panic(err)
	}
}

// waitForTx waits for a transactions to be confirmed with exponential back-off
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

// DeployDummyApp deploys a dummy application (smart contract) that is used for cost pool increase
func DeployDummyApp(approvalProgram, clearProgram []byte, appCreatorSK ed25519.PrivateKey, algodClient *algod.Client,
	suggestedParams types.SuggestedParams) (uint64, error) {
	sender, err := crypto.GenerateAddressFromSK(appCreatorSK)
	if err != nil {
		return 0, err
	}
	tx, err := future.MakeApplicationCreateTx(
		false,
		approvalProgram,
		clearProgram,
		types.StateSchema{},
		types.StateSchema{},
		nil,
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
		return 0, err
	}
	_, stxBytes, err := crypto.SignTransaction(appCreatorSK, tx)
	if err != nil {
		return 0, err
	}
	if err != nil {
		return 0, err
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

// DeployABIApp deploys the beacon's smart contract
func DeployABIApp(startingRound, dummyAppID uint64, algodClient *algod.Client, vrfPublicKey ed25519.PublicKey,
	appCreatorAccount crypto.Account, vrfProof, approvalBytes, clearBytes []byte,
	suggestedParams types.SuggestedParams) (uint64, error) {
	globalStateSchema := types.StateSchema{
		NumUint:      0,
		NumByteSlice: 64,
	}

	localStateSchema := types.StateSchema{
		NumUint:      0,
		NumByteSlice: 0,
	}
	var atc future.AtomicTransactionComposer
	signer := future.BasicAccountTransactionSigner{Account: appCreatorAccount}
	methodSig := "create_app(uint64,byte[80],byte[32])void"
	method, err := abi.MethodFromSignature(methodSig)
	if err != nil {
		return 0, fmt.Errorf("error abi.MethodFromSignature(methodSig) %v", err)
	}
	suggestedParams.FirstRoundValid = types.Round(startingRound + 1)
	suggestedParams.LastRoundValid = suggestedParams.FirstRoundValid + 1000
	var vrfProofArray [VrfProofLen]byte
	copy(vrfProofArray[:], vrfProof)
	methodCallParams := future.AddMethodCallParams{
		Method:          method,
		MethodArgs:      []interface{}{startingRound, vrfProofArray, vrfPublicKey[:]},
		Sender:          appCreatorAccount.Address,
		SuggestedParams: suggestedParams,
		OnComplete:      types.NoOpOC,
		ApprovalProgram: approvalBytes,
		ClearProgram:    clearBytes,
		GlobalSchema:    globalStateSchema,
		LocalSchema:     localStateSchema,
		Signer:          signer,
	}
	err = atc.AddMethodCall(methodCallParams)
	if err != nil {
		return 0, fmt.Errorf("error atc.AddMethodCall(methodCallParams) %v", err)
	}

	for i := 0; i < NumOfDummyTxns; i++ {
		dummyAppCall, err := future.MakeApplicationNoOpTx(
			dummyAppID,
			nil,
			nil,
			nil,
			nil,
			suggestedParams,
			appCreatorAccount.Address,
			[]byte{byte(i)},
			types.Digest{},
			[32]byte{},
			types.ZeroAddress,
		)
		if err != nil {
			return 0, fmt.Errorf("failed creating dummy app call: %v", err)
		}
		err = atc.AddTransaction(future.TransactionWithSigner{
			Txn:    dummyAppCall,
			Signer: signer,
		})
		if err != nil {
			return 0, fmt.Errorf("error atc.AddTransaction(future.TransactionWithSigner{ %v", err)
		}
	}
	stxsSlice, err := atc.GatherSignatures()
	if err != nil {
		return 0, fmt.Errorf("error in atc.GatherSignatures: %w", err)
	}
	var stxBytes []byte
	for _, stx := range stxsSlice {
		stxBytes = append(stxBytes, stx...)
	}

	txID, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		//log.Debugf("stxbytes bas64: %v", base64.StdEncoding.EncodeToString(stxBytes))
		return 0, fmt.Errorf("failed sending app call: %v", err)
	}
	res, err := waitForTx(algodClient, txID)
	if err != nil {
		return 0, err
	}
	return res.ApplicationIndex, nil
}

// createABIAppWithVRFKey deploys the beacon's smart contract after computing the initial VRF proof to be verified
func createABIAppWithVRFKey(startingRound, dummyAppID uint64, algodClient *algod.Client,
	vrfPrivateKey ed25519.PrivateKey, appCreatorAccount crypto.Account, approvalBytes, clearBytes []byte,
	suggestedParams types.SuggestedParams) (uint64, error) {

	log.Infof("getting block seed for %d", startingRound)
	block, err := getBlock(algodClient, startingRound)
	if err != nil {
		return 0, fmt.Errorf("error getting block seed of block %d from algod", startingRound)
	}

	blockNumberBytes := convertUint64ToBigEndianBytes(startingRound)
	vrfOutput, vrfProof, err := computeAndSignVrf(
		blockNumberBytes,
		block.Seed[:],
		vrfPrivateKey,
	)
	if err != nil {
		return 0, fmt.Errorf("failed computing vrf for %d: %v", startingRound, err)
	}
	log.Debugf("proof B64 is %s", base64.StdEncoding.EncodeToString(vrfProof))
	vrfOutputsHistory[startingRound] = vrfOutput
	return DeployABIApp(startingRound, dummyAppID, algodClient, vrfPrivateKey.Public().(ed25519.PublicKey),
		appCreatorAccount, vrfProof, approvalBytes, clearBytes, suggestedParams)
}

// CompileTeal compiles an approval and clear programs given 2 corresponding TEAL script files
func CompileTeal(approvalProgramFilename, clearProgramFilename string, algodClient *algod.Client) (
	[]byte, []byte, error) {
	// #nosec G304
	approval, err := ioutil.ReadFile(approvalProgramFilename)
	if err != nil {
		return nil, nil, err
	}
	// #nosec G304
	clear, err := ioutil.ReadFile(clearProgramFilename)
	if err != nil {
		return nil, nil, err
	}
	compiledApprovalObject, err := algodClient.TealCompile(approval).Do(context.Background())
	if err != nil {
		return nil, nil, err
	}
	compiledClearObject, err := algodClient.TealCompile(clear).Do(context.Background())
	if err != nil {
		return nil, nil, err
	}

	compiledApprovalBytes, err := base64.StdEncoding.DecodeString(compiledApprovalObject.Result)
	if err != nil {
		return nil, nil, err
	}
	compiledClearBytes, err := base64.StdEncoding.DecodeString(compiledClearObject.Result)
	if err != nil {
		return nil, nil, err
	}

	return compiledApprovalBytes, compiledClearBytes, nil
}

// getLatestRound get the latest block round with exponential back-off
func getLatestRound(algodClient *algod.Client) (uint64, error) {
	var status models.NodeStatus
	err := tools.Retry(1, 5,
		func() error {
			var err error
			status, err = algodClient.Status().Do(context.Background())
			return err
		},
		func(err error) {
			log.Warnf("failed to get status from algod, trying again...: %v", err)
		},
	)
	return status.LastRound, err
}

// floorToMultipleOfX gets the highest multiple of x that is lower than num
func floorToMultipleOfX(num, x uint64) uint64 {
	return (num / x) * x
}

// ceilingToMultipleOfX gets the lowest multiple of x that is higher than num
func ceilingToMultipleOfX(num, x uint64) uint64 {
	return ((num + x - 1) / x) * x
}

// mainLoop is the main function of the daemon that computes and submits VRF proofs and runs tests round by round.
// It stops running only in case of an error or an interrupt
func mainLoop(appID, dummyAppID, startingRound uint64, algodClient *algod.Client,
	vrfPrivateKey ed25519.PrivateKey, serviceAccount crypto.Account) {
	currentRoundHandled := startingRound + VrfRoundMultiple
	isRecovering := false
	for {
		latestBlockRound, err := getLatestRound(algodClient)
		if err != nil {
			log.Errorf("failed to get status from algod")
			return
		}
		suggestedParams, err := GetSuggestedParams(algodClient)
		if err != nil {
			log.Errorf("failed getting suggestedParams from algod")
			return
		}
		if !isRecovering {
			// we had these dummy txns in order to add new blocks since we're running in dev mode
			// we don't do this in recovery in order to quickly finish recovery
			if currentRoundHandled%VrfRoundMultiple != 0 {
				sendDummyTxn(algodClient, serviceAccount, suggestedParams)
			}
			sleepTime := time.Duration(WaitBetweenBlocksMS) * time.Millisecond
			time.Sleep(sleepTime)
		}
		// assuming testing on sandnet in dev mode (one block is created for a new transaction)
		nextBlockRound := latestBlockRound + 1
		// check if we are in recovery
		// we can only get the block seed of rounds [latestBlockRound - NbRetainedBlocks, latestBlockRound],
		// thus we enter recovery if we currently handle rounds that are < latestBlockRound - NbRetainedBlocks
		if currentRoundHandled%VrfRoundMultiple == 0 && latestBlockRound > currentRoundHandled+NbRetainedBlocks {
			// once we hit recovery mode, the next round handled is the first multiple of 8 that is inside the
			// [nextBlockRound - NbRetainedBlocks, nextBlockRound] range
			currentRoundHandled = floorToMultipleOfX(nextBlockRound-NbRetainedBlocks+VrfRoundMultiple, VrfRoundMultiple)
			isRecovering = true
			log.Infof("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ starting recovery from round %d",
				currentRoundHandled)
		} else if latestBlockRound-currentRoundHandled <= 10 && isRecovering {
			log.Infof("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ finished recovery")
			isRecovering = false
		}

		if currentRoundHandled%VrfRoundMultiple == 0 {
			log.Infof("getting block seed for %d", currentRoundHandled)
			block, err := getBlock(algodClient, currentRoundHandled)
			if err != nil {
				log.Errorf("error getting block seed of block %d from algod", currentRoundHandled)
				return
			}
			suggestedParams.FirstRoundValid = types.Round(currentRoundHandled + 1)
			suggestedParams.LastRoundValid = suggestedParams.FirstRoundValid + 1000
			err = handleCurrentRound(currentRoundHandled, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient,
				suggestedParams, block.Seed[:])
			if err != nil {
				log.Errorf("error handling requests for current round %d: %v", currentRoundHandled, err)
				return
			}
			if !isRecovering {
				err = runSomeTests(currentRoundHandled, appID, dummyAppID, serviceAccount, algodClient)
				if err != nil {
					log.Errorf("failed tests: %v", err)
					return
				}
			} else {
				log.Debugf("not testing - in recovery")
			}
		}
		currentRoundHandled++
	}
}

// GetStartingRound figures out the round that we start the daemon with, according to the latest round from algod
// and input from the user
func GetStartingRound(inputRound uint64, algodClient *algod.Client) (uint64, error) {
	var result uint64
	if inputRound != 0 {
		result = inputRound
	} else {
		lastRound, err := getLatestRound(algodClient)
		if err != nil {
			return 0, fmt.Errorf("failed getting status from algod: %v", err)
		}
		result = lastRound
	}
	// get the next round that is a multiple of 8
	result = ceilingToMultipleOfX(result, VrfRoundMultiple)
	return result, nil
}

// convertUint64ToBigEndianBytes is self-explanatory
func convertUint64ToBigEndianBytes(num uint64) []byte {
	res := make([]byte, 8)
	binary.BigEndian.PutUint64(res, num)
	return res
}

var RunDaemonCmd = &cobra.Command{
	Use:   "run-daemon",
	Short: "runs the daemon",
	Run: func(cmd *cobra.Command, args []string) {
		err := tools.TestEnvironmentVariables(AlgodAddress)
		if err != nil {
			log.Error(err)
			return
		}
		algodClient, err := tools.InitClients(AlgodAddress, AlgodToken)
		if err != nil {
			log.Error(err)
			return
		}
		startingRound, err = GetStartingRound(startingRound, algodClient)
		if err != nil {
			log.Error(err)
			return
		}

		// vrfPrivateKey is key used to generate VRF proofs
		vrfPrivateKey, err := mnemonic.ToPrivateKey(vrfMnemonicString)
		if err != nil {
			log.Errorf("invalid vrf mnemonic: %v", err)
			return
		}
		// servicePrivateKey is the key used to send transactions
		servicePrivateKey, err := mnemonic.ToPrivateKey(serviceMnemonicString)
		if err != nil {
			log.Errorf("invalid service mnemonic: %v", err)
			return
		}
		serviceAccount, err := crypto.AccountFromPrivateKey(servicePrivateKey)
		if err != nil {
			log.Errorf("error in crypto.AccountFromPrivateKey: %v", err)
			return
		}

		suggestedParams, err := GetSuggestedParams(algodClient)
		if err != nil {
			log.Errorf("error getting suggested params from algod: %v", err)
			return
		}
		// since we are using sandbox with dev configuration, we need to send transactions to add more blocks
		for i := 0; i < 13; i++ {
			sendDummyTxn(algodClient, serviceAccount, suggestedParams)
		}

		log.Info("creating dummy app...")
		dummyApprovalBytes, dummyClearBytes, err := CompileTeal(dummyAppApprovalFilename, dummyAppClearFilename,
			algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		dummyAppID, err := DeployDummyApp(dummyApprovalBytes, dummyClearBytes, servicePrivateKey, algodClient,
			suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("dummy app id: %d\n", dummyAppID)
		log.Info("creating the randomness beacon's ABI app...")
		approvalBytes, clearBytes, err := CompileTeal(approvalProgramFilename, clearProgramFilename, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		vrfOutputsHistory = make(map[uint64][]byte)
		appID, err := createABIAppWithVRFKey(
			startingRound, dummyAppID, algodClient, vrfPrivateKey,
			serviceAccount, approvalBytes, clearBytes, suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("app id: %d\n", appID)

		resultsHistory = make(map[string]Result)

		log.Info("running...")

		mainLoop(
			appID,
			dummyAppID,
			startingRound,
			algodClient,
			vrfPrivateKey,
			serviceAccount,
		)
		//cmd.HelpFunc()(cmd, args)
	},
}
