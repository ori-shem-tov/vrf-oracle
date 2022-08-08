package daemon

import (
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/algorand/go-algorand-sdk/abi"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/libsodium-wrapper"
	models2 "github.com/ori-shem-tov/vrf-oracle/models"
	"github.com/ori-shem-tov/vrf-oracle/tools"
	"io/ioutil"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/spf13/cobra"
)

var (
	appCreatorMnemonic      string
	approvalProgramFilename string
	clearProgramFilename    string
	signingMnemonicString   string // the mnemonic for signing vrf responses
	vrfMnemonicString       string // the mnemonic for generating the vrf
	serviceMnemonicString   string // the mnemonic for the service account (used to send responses to the smart-contract)
	startingRound           uint64 // the round from which the daemon starts scanning
	AlgodAddress            = os.Getenv("AF_ALGOD_ADDRESS")
	AlgodToken              = os.Getenv("AF_ALGOD_TOKEN")
	logLevelEnv             = strings.ToLower(os.Getenv("VRF_LOG_LEVEL"))
)

const (
	waitBetweenBlocksMS = 4500
	numOfDummyTxns      = 10
)

func MarkFlagRequired(flag *pflag.FlagSet, name string) {
	err := cobra.MarkFlagRequired(flag, name)
	if err != nil {
		panic(err)
	}
}

func SetLogger() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	logLevel := log.WarnLevel
	if logLevelEnv == "debug" {
		logLevel = log.DebugLevel
	} else if logLevelEnv == "info" {
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
}

func init() {
	SetLogger()

	RunDaemonCmd.Flags().StringVar(&signingMnemonicString, "signing-mnemonic", "",
		"25-word mnemonic of the oracle for signing (required)")
	MarkFlagRequired(RunDaemonCmd.Flags(), "signing-mnemonic")

	RunDaemonCmd.Flags().StringVar(&vrfMnemonicString, "vrf-mnemonic", "",
		"25-word mnemonic of the oracle for computing vrf (required)")
	MarkFlagRequired(RunDaemonCmd.Flags(), "vrf-mnemonic")

	RunDaemonCmd.Flags().StringVar(&serviceMnemonicString, "service-mnemonic", "",
		"25-word mnemonic of the service for writing the response (required)")
	MarkFlagRequired(RunDaemonCmd.Flags(), "service-mnemonic")

	RunDaemonCmd.Flags().Uint64Var(&startingRound, "round", 0,
		"the round to start scanning from (optional. default: current round)")

	RunDaemonCmd.Flags().StringVar(&appCreatorMnemonic, "app-creator-mnemonic", "", "25-word mnemonic of the app creator (required)")
	MarkFlagRequired(RunDaemonCmd.Flags(), "app-creator-mnemonic")

	RunDaemonCmd.Flags().StringVar(&approvalProgramFilename, "approval-program", "", "TEAL script of the approval program (required)")
	MarkFlagRequired(RunDaemonCmd.Flags(), "approval-program")

	RunDaemonCmd.Flags().StringVar(&clearProgramFilename, "clear-program", "", "TEAL script of the clear program (required)")
	MarkFlagRequired(RunDaemonCmd.Flags(), "clear-program")

}

func computeWaitFactor(roundFromIndexer uint64, roundToFetch uint64) float64 {
	// keep pace with the indexer
	// if the service is far behind the indexer, wait time will decrease
	if roundFromIndexer <= roundToFetch {
		return 1
	}
	return 1 / float64(roundFromIndexer-roundToFetch)
}

func addGetMethodCall(atc *future.AtomicTransactionComposer, round, appID uint64, serviceAccount crypto.Account, sp types.SuggestedParams) error {
	signer := future.BasicAccountTransactionSigner{Account: serviceAccount}
	methodSig := "get(uint64,string)string"
	method, err := abi.MethodFromSignature(methodSig)
	if err != nil {
		return fmt.Errorf("error abi.MethodFromSignature(methodSig) %v", err)
	}
	methodCallParams := future.AddMethodCallParams{
		AppID:           appID,
		Method:          method,
		MethodArgs:      []interface{}{round, ""},
		Sender:          serviceAccount.Address,
		SuggestedParams: sp,
		OnComplete:      0,
		ExtraPages:      0,
		Note:            nil,
		Lease:           [32]byte{},
		RekeyTo:         types.Address{},
		Signer:          signer,
		ForeignApps:     nil,
		ForeignAssets:   nil,
		ForeignAccounts: nil,
	}
	err = atc.AddMethodCall(methodCallParams)
	if err != nil {
		return fmt.Errorf("error atc.AddMethodCall(methodCallParams) %v", err)
	}
	return nil
}

// generates a group of 3 application calls:
// the 1st App call is to the smart-contract to respond the VRF output, while the 2nd and 3rd are dummy app calls used
// to increase the cost pool.
func buildAnswerPhaseTransactionsGroupABI(appID, dummyAppID uint64, serviceAccount crypto.Account, vrfRequest models2.VrfRequest,
	vrfOutput []byte, sp types.SuggestedParams) ([]byte, error) {

	var atc future.AtomicTransactionComposer
	signer := future.BasicAccountTransactionSigner{Account: serviceAccount}
	methodSig := "submit(uint64,string)void"
	method, err := abi.MethodFromSignature(methodSig)
	if err != nil {
		return nil, fmt.Errorf("error abi.MethodFromSignature(methodSig) %v", err)
	}
	sp.FirstRoundValid = types.Round(vrfRequest.BlockNumber + 1)
	sp.LastRoundValid = sp.FirstRoundValid + 1000
	log.Debugf("starting round %d", vrfRequest.BlockNumber)
	methodCallParams := future.AddMethodCallParams{
		AppID:           appID,
		Method:          method,
		MethodArgs:      []interface{}{vrfRequest.BlockNumber, string(vrfOutput)},
		Sender:          serviceAccount.Address,
		SuggestedParams: sp,
		OnComplete:      0,
		ExtraPages:      0,
		Note:            nil,
		Lease:           [32]byte{},
		RekeyTo:         types.Address{},
		Signer:          signer,
		ForeignApps:     nil,
		ForeignAssets:   nil,
		ForeignAccounts: nil,
	}
	err = atc.AddMethodCall(methodCallParams)
	if err != nil {
		return nil, fmt.Errorf("error atc.AddMethodCall(methodCallParams) %v", err)
	}

	for i := 0; i < numOfDummyTxns; i++ {
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
	err = addGetMethodCall(&atc, vrfRequest.BlockNumber, appID, serviceAccount, sp)
	if err != nil {
		return nil, fmt.Errorf("error addGetMethodCall(&atc, vrfRequest.BlockNumber, appID, serviceAccount, sp) %v", err)
	}
	stxsSlice, err := atc.GatherSignatures()
	lastStx := stxsSlice[len(stxsSlice)-1]
	var lastObj types.SignedTxn
	err = msgpack.Decode(lastStx, &lastObj)
	if err != nil {
		return nil, fmt.Errorf("error msgpack.Decode(lastStx, &lastObj) %v", err)
	}
	lastTxID := crypto.GetTxID(lastObj.Txn)
	log.Debugf("last TXID is %s", lastTxID)
	var stxBytes []byte
	for _, stx := range stxsSlice {
		stxBytes = append(stxBytes, stx...)
	}
	return stxBytes, nil
}

func getVrfPrivateKey(key ed25519.PrivateKey) libsodium_wrapper.VrfPrivkey {
	var vrfPrivateKey libsodium_wrapper.VrfPrivkey
	copy(vrfPrivateKey[:], key)
	return vrfPrivateKey
}

// concat the block number with the block seed and the user seed and hash to create the input to the VRF
func buildVrfInput(blockNumber, blockSeed []byte) [sha512.Size256]byte {
	toHash := append(blockNumber, blockSeed...)
	return sha512.Sum512_256(toHash)
}

// compute the VRF output and sign the concatenation of the input with the output (to be verified by the smart contract)
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

// handles requests for the current round: computes the VRF output and sends it to the smart-contract
func handleRequestsForCurrentRound(requestsToHandle []models2.VrfRequest, blockSeed []byte,
	vrfPrivateKey ed25519.PrivateKey, serviceAccount crypto.Account,
	suggestedParams types.SuggestedParams, appID, dummyAppID uint64, algodClient *algod.Client) {
	for _, currentRequestHandled := range requestsToHandle {
		vrfOutput, vrfProof, err := computeAndSignVrf(
			currentRequestHandled.BlockNumberBytes,
			blockSeed,
			vrfPrivateKey,
		)
		if err != nil {
			log.Warnf("failed computing vrf for %v: %v. skipping...", currentRequestHandled, err)
			continue
		}
		toHash := vrfOutput
		hashedOutput := sha512.Sum512_256(toHash)
		hashedOutput = sha512.Sum512_256(hashedOutput[:])
		hashedOutputB64 := base64.StdEncoding.EncodeToString(hashedOutput[:])
		log.Debugf("hashed output (b64) for round %d is %v", currentRequestHandled.BlockNumber, hashedOutputB64)
		stxBytes, err := buildAnswerPhaseTransactionsGroupABI(
			appID,
			dummyAppID,
			serviceAccount,
			currentRequestHandled,
			vrfProof,
			suggestedParams,
		)
		if err != nil {
			log.Warnf(
				"failed building transactions group for %v: %v. skipping...",
				currentRequestHandled,
				err,
			)
			continue
		}
		txId, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
		if err != nil {
			log.Warnf(
				"failed sending transactions group for %v: %v. skipping...",
				currentRequestHandled,
				err,
			)
			//log.Debugf("stxbytes bas64: %v", base64.StdEncoding.EncodeToString(stxBytes))
			continue
		}
		log.Infof("Sent transaction %s", txId)

	}
}

// getting suggested params with exponential back-off
func getSuggestedParams(algodClient *algod.Client) (types.SuggestedParams, error) {
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

// getting a block with exponential back-off
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

// extracts the VRF requests from the heap to handle in the current round
func getVrfRequestsToHandle(h *tools.VrfRequestsHeap, currentRound uint64) []models2.VrfRequest {
	var result []models2.VrfRequest
	for {
		if len(*h) < 1 {
			break
		}
		top := (*h)[0]
		if top.BlockNumber > currentRound {
			log.Infof("handled all requests for round %d", currentRound)
			break
		}
		currentNoteHandled := heap.Pop(h).(models2.VrfRequest)
		if currentNoteHandled.BlockNumber < currentRound {
			log.Warnf("found unhandled old request in queue: %v", currentNoteHandled)
			continue
		}
		result = append(result, currentNoteHandled)
	}
	return result
}

func storeRequestsInHeap(h *tools.VrfRequestsHeap, currentRound uint64) {
	if currentRound%8 == 0 {
		blockNumberBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(blockNumberBytes, currentRound)
		heap.Push(h, models2.VrfRequest{
			Sender:           types.Address{},
			BlockNumber:      currentRound,
			BlockNumberBytes: blockNumberBytes,
			UserSeed:         nil,
		})
		log.Debugf("adding request for round %d", currentRound)
	}
}

func sendDummyTxn(algodClient *algod.Client, serviceAccount crypto.Account) {
	suggestedParams, err := getSuggestedParams(algodClient)
	if err != nil {
		panic(err)
	}
	note := make([]byte, 32)
	crypto.RandomBytes(note)
	txn, err := future.MakePaymentTxn(
		serviceAccount.Address.String(),
		serviceAccount.Address.String(),
		0,
		note,
		"",
		suggestedParams,
	)
	if err != nil {
		panic(err)
	}
	_, stx, err := crypto.SignTransaction(serviceAccount.PrivateKey, txn)
	if err != nil {
		panic(err)
	}
	_, err = algodClient.SendRawTransaction(stx).Do(context.Background())
	if err != nil {
		panic(err)
	}
}

func generateSignedDummyAppCreate(approvalBytes, clearBytes []byte, globalState, localState types.StateSchema,
	appCreatorSK ed25519.PrivateKey, args [][]byte, sp types.SuggestedParams) ([]byte, error) {
	sender, err := crypto.GenerateAddressFromSK(appCreatorSK)
	if err != nil {
		return nil, err
	}
	tx, err := future.MakeApplicationCreateTx(
		false,
		approvalBytes,
		clearBytes,
		globalState,
		localState,
		args,
		nil,
		nil,
		nil,
		sp,
		sender,
		nil,
		types.Digest{},
		[32]byte{},
		types.ZeroAddress,
	)
	if err != nil {
		return nil, err
	}
	_, stxBytes, err := crypto.SignTransaction(appCreatorSK, tx)
	if err != nil {
		return nil, err
	}
	return stxBytes, nil
}

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

func createDummyApp(approvalProgram []byte, appCreatorSK ed25519.PrivateKey, algodClient *algod.Client,
	suggestedParams types.SuggestedParams) (uint64, error) {
	stxBytes, err := generateSignedDummyAppCreate(approvalProgram, approvalProgram, types.StateSchema{},
		types.StateSchema{}, appCreatorSK, nil, suggestedParams)
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

func createABIApp(startingRound, dummyAppID uint64, algodClient *algod.Client, vrfPrivateKey,
	appCreatorPrivateKey ed25519.PrivateKey, approvalBytes, clearBytes []byte,
	suggestedParams types.SuggestedParams) (uint64, error) {

	log.Infof("getting block seed for %d", startingRound)
	block, err := getBlock(algodClient, startingRound)
	if err != nil {
		return 0, fmt.Errorf("error getting block seed of block %d from algod", startingRound)
	}

	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, startingRound)
	_, vrfProof, err := computeAndSignVrf(
		blockNumberBytes,
		block.Seed[:],
		vrfPrivateKey,
	)
	if err != nil {
		return 0, fmt.Errorf("failed computing vrf for %d: %v", startingRound, err)
	}
	globalStateSchema := types.StateSchema{
		NumUint:      0,
		NumByteSlice: 64,
	}

	localStateSchema := types.StateSchema{
		NumUint:      0,
		NumByteSlice: 0,
	}
	var atc future.AtomicTransactionComposer
	appCreatorAccount, err := crypto.AccountFromPrivateKey(appCreatorPrivateKey)
	if err != nil {
		return 0, fmt.Errorf("error crypto.AccountFromPrivateKey(appCreatorPrivateKey) %v", err)
	}
	signer := future.BasicAccountTransactionSigner{Account: appCreatorAccount}
	methodSig := "create_app(uint64,string,address)void"
	method, err := abi.MethodFromSignature(methodSig)
	if err != nil {
		return 0, fmt.Errorf("error abi.MethodFromSignature(methodSig) %v", err)
	}
	suggestedParams.FirstRoundValid = types.Round(startingRound + 1)
	suggestedParams.LastRoundValid = suggestedParams.FirstRoundValid + 1000
	methodCallParams := future.AddMethodCallParams{
		AppID:           0,
		Method:          method,
		MethodArgs:      []interface{}{startingRound, string(vrfProof), vrfPrivateKey[32:]},
		Sender:          appCreatorAccount.Address,
		SuggestedParams: suggestedParams,
		OnComplete:      0,
		ApprovalProgram: approvalBytes,
		ClearProgram:    clearBytes,
		GlobalSchema:    globalStateSchema,
		LocalSchema:     localStateSchema,
		ExtraPages:      0,
		Note:            nil,
		Lease:           [32]byte{},
		RekeyTo:         types.Address{},
		Signer:          signer,
		ForeignApps:     nil,
		ForeignAssets:   nil,
		ForeignAccounts: nil,
	}
	err = atc.AddMethodCall(methodCallParams)
	if err != nil {
		return 0, fmt.Errorf("error atc.AddMethodCall(methodCallParams) %v", err)
	}

	for i := 0; i < numOfDummyTxns; i++ {
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

func compileTeal(approvalProgramFilename, clearProgramFilename string, algodClient *algod.Client) ([]byte, []byte, error) {
	approval, err := ioutil.ReadFile(approvalProgramFilename)
	if err != nil {
		return nil, nil, err
	}
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

func mainLoop(startingRound, appID, dummyAppID uint64, algodClient *algod.Client,
	vrfPrivateKey ed25519.PrivateKey, serviceAccount crypto.Account) {
	waitFactor := float64(1)
	currentRound := startingRound
	h := &tools.VrfRequestsHeap{}
	heap.Init(h)
	for {
		sendDummyTxn(algodClient, serviceAccount)
		sleepTime := time.Duration(waitFactor*waitBetweenBlocksMS) * time.Millisecond
		log.Debugf("sleeping %v", sleepTime)
		time.Sleep(sleepTime)

		storeRequestsInHeap(h, currentRound)

		requestsToHandle := getVrfRequestsToHandle(h, currentRound)
		if len(requestsToHandle) != 0 {
			log.Infof("getting block seed for %d", currentRound)
			block, err := getBlock(algodClient, currentRound)
			if err != nil {
				log.Errorf("error getting block seed of block %d from algod", currentRound)
				return
			}

			suggestedParams, err := getSuggestedParams(algodClient)
			if err != nil {
				log.Errorf("error getting suggested params from algod: %v", err)
				return
			}
			handleRequestsForCurrentRound(
				requestsToHandle,
				block.Seed[:],
				vrfPrivateKey,
				serviceAccount,
				suggestedParams,
				appID,
				dummyAppID,
				algodClient,
			)
		}

		waitFactor = computeWaitFactor(currentRound, currentRound)
		currentRound++
	}
}

func getStartingRound(inputRound uint64, algodClient *algod.Client) (uint64, error) {
	var result uint64
	if inputRound != 0 {
		result = inputRound
	} else {
		status, err := algodClient.Status().Do(context.Background())
		if err != nil {
			return 0, fmt.Errorf("failed getting status from algod: %v", err)
		}
		result = status.LastRound
	}
	return result, nil
}

func InitClients(algodAddress, algodToken string) (*algod.Client, error) {
	var failedClients []string
	algodClient, err := algod.MakeClient(algodAddress, algodToken)
	if err != nil {
		failedClients = append(failedClients, "algod")
		log.Error(err)
	}
	if len(failedClients) > 0 {
		err = fmt.Errorf("failed creating the following client(s): %s", strings.Join(failedClients, ","))
	}
	return algodClient, err
}

func TestEnvironmentVariables() error {
	var missing []string
	if AlgodAddress == "" {
		missing = append(missing, "AF_ALGOD_ADDRESS")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s environment variable(s)", strings.Join(missing, ","))
	}
	return nil
}

var RunDaemonCmd = &cobra.Command{
	Use:   "run-daemon",
	Short: "runs the daemon",
	Run: func(cmd *cobra.Command, args []string) {
		err := TestEnvironmentVariables()
		if err != nil {
			log.Error(err)
			return
		}
		algodClient, err := InitClients(AlgodAddress, AlgodToken)
		if err != nil {
			log.Error(err)
			return
		}
		startingRound, err = getStartingRound(startingRound, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		startingRound = (startingRound / 8) * 8
		vrfPrivateKey, err := mnemonic.ToPrivateKey(vrfMnemonicString)
		if err != nil {
			log.Errorf("invalid vrf mnemonic: %v", err)
			return
		}
		appCreatorPrivateKey, err := mnemonic.ToPrivateKey(appCreatorMnemonic)
		if err != nil {
			log.Errorf("invalid app creator mnemonic: %v", err)
			return
		}
		servicePrivateKey, err := mnemonic.ToPrivateKey(serviceMnemonicString)
		if err != nil {
			log.Errorf("invalid service mnemonic: %v", err)
			return
		}
		serviceAddress, err := crypto.GenerateAddressFromSK(servicePrivateKey)
		serviceAccount := crypto.Account{
			PrivateKey: servicePrivateKey,
			Address:    serviceAddress,
		}

		suggestedParams, err := getSuggestedParams(algodClient)
		if err != nil {
			log.Errorf("error getting suggested params from algod: %v", err)
			return
		}

		log.Info("creating dummy app...")
		dummyAppID, err := createDummyApp([]byte{0x07, 0x20, 0x01, 0x01, 0x22}, appCreatorPrivateKey, algodClient,
			suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("dummy app id: %d\n", dummyAppID)
		// dirty workaround for weird issue where no blocks are added if no transactions
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		log.Info("creating ABI app...")
		approvalBytes, clearBytes, err := compileTeal(approvalProgramFilename, clearProgramFilename, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		appID, err := createABIApp(
			startingRound, dummyAppID, algodClient, vrfPrivateKey,
			appCreatorPrivateKey, approvalBytes, clearBytes, suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("app id: %d\n", appID)

		startingRound += 8

		log.Info("running...")
		// dirty workaround for weird issue where no blocks are added if no transactions
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)
		sendDummyTxn(algodClient, serviceAccount)

		mainLoop(
			startingRound,
			appID,
			dummyAppID,
			algodClient,
			vrfPrivateKey,
			serviceAccount,
		)
		//cmd.HelpFunc()(cmd, args)
	},
}
