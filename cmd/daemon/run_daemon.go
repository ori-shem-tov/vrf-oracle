package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math"
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
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"

	"github.com/ori-shem-tov/vrf-oracle/libsodium-wrapper"
	"github.com/ori-shem-tov/vrf-oracle/tools"
)

type Result struct {
	Round    uint64
	UserData []byte
	Method   string
}

var (
	appCreatorMnemonic       string
	approvalProgramFilename  string
	clearProgramFilename     string
	dummyAppApprovalFilename string
	dummyAppClearFilename    string
	vrfMnemonicString        string // the mnemonic for generating the vrf
	serviceMnemonicString    string // the mnemonic for the service account (used to send responses to the smart-contract)
	startingRound            uint64 // the round from which the daemon starts scanning
	AlgodAddress             = os.Getenv("AF_ALGOD_ADDRESS")
	AlgodToken               = os.Getenv("AF_ALGOD_TOKEN")
	logLevelEnv              = strings.ToLower(os.Getenv("VRF_LOG_LEVEL"))
	vrfOutputsHistory        [][]byte
	resultsHistory           map[string]Result
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
	VrfPkLen           = 32
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

	RunDaemonCmd.Flags().StringVar(&appCreatorMnemonic, "app-creator-mnemonic", "", "25-word mnemonic of the app creator (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "app-creator-mnemonic")

	RunDaemonCmd.Flags().StringVar(&approvalProgramFilename, "approval-program", "", "TEAL script of the approval program (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "approval-program")

	RunDaemonCmd.Flags().StringVar(&clearProgramFilename, "clear-program", "", "TEAL script of the clear program (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "clear-program")

	RunDaemonCmd.Flags().StringVar(&dummyAppApprovalFilename, "dummy-app-approval", "", "TEAL script of the dummy app approval (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "dummy-app-approval")

	RunDaemonCmd.Flags().StringVar(&dummyAppClearFilename, "dummy-app-clear", "", "TEAL script of the dummy app clear (required)")
	tools.MarkFlagRequired(RunDaemonCmd.Flags(), "dummy-app-clear")

}

func addGetOrMustGetMethodCall(atc *future.AtomicTransactionComposer, round, appID uint64, serviceAccount crypto.Account,
	sp types.SuggestedParams, userData []byte, methodName string) error {
	signer := future.BasicAccountTransactionSigner{Account: serviceAccount}
	methodSig := fmt.Sprintf("%s(uint64,byte[])byte[]", methodName)
	method, err := abi.MethodFromSignature(methodSig)
	if err != nil {
		return fmt.Errorf("error abi.MethodFromSignature(methodSig) %v", err)
	}
	methodCallParams := future.AddMethodCallParams{
		AppID:           appID,
		Method:          method,
		MethodArgs:      []interface{}{round, userData},
		Sender:          serviceAccount.Address,
		SuggestedParams: sp,
		Note:            nil,
		Signer:          signer,
	}
	err = atc.AddMethodCall(methodCallParams)
	if err != nil {
		return fmt.Errorf("error atc.AddMethodCall(methodCallParams) %v", err)
	}
	return nil
}

func getRandomUserData() []byte {
	res := make([]byte, 10)
	_, err := rand.Read(res)
	if err != nil {
		panic(err)
	}
	return res
}

func getVrfOutputForRound(round uint64) []byte {
	return vrfOutputsHistory[(round-startingRound)/8]
}

func convertUint64ToBigEndianBytes(num uint64) []byte {
	res := make([]byte, 8)
	binary.BigEndian.PutUint64(res, num)
	return res
}

func testNonMultipleOf8Rounds(round, appID uint64, serviceAccount crypto.Account, vrfOutput []byte, sp types.SuggestedParams,
	algodClient *algod.Client) error {

	var atc future.AtomicTransactionComposer
	for i := 0; i < 7; i++ {
		r := uint64(i) + round - 7
		err := addGetOrMustGetMethodCall(&atc, r, appID, serviceAccount, sp, []byte{}, "get")
		if err != nil {
			return fmt.Errorf("error in addGetOrMustGetMethodCall for round %d: %v", r, err)
		}
		err = addGetOrMustGetMethodCall(&atc, r, appID, serviceAccount, sp, []byte{}, "must_get")
		if err != nil {
			return fmt.Errorf("error in addGetOrMustGetMethodCall for round %d: %v", r, err)
		}
	}
	result, err := atc.Execute(algodClient, context.Background(), 3)
	if err != nil {
		return fmt.Errorf("error in atc.Execute for round %d: %v", round, err)
	}
	if len(result.MethodResults) != 7*2 {
		return fmt.Errorf("didn't get enough MethodResults for round %d", round)
	}

	storedVRFOutput := vrfOutput[:StoredVrfOutputLen] // we truncate the VRF output to StoredVrfOutputLen bytes

	for i := 0; i < 7; i++ {
		r := uint64(i) + round - 7
		// Verify the random output matches what it should be
		roundBytes := convertUint64ToBigEndianBytes(r)
		hashedOutput := sha3.Sum256(append(storedVRFOutput[:], roundBytes...))
		// ABI adds 0x0020 at the beginning, as it's the length of the output
		abiHashedOutputB64 := base64.StdEncoding.EncodeToString(append([]byte{0x00, 0x20}, hashedOutput[:]...))
		b64ReturnedFromGet := base64.StdEncoding.EncodeToString(result.MethodResults[2*i+0].RawReturnValue)
		b64ReturnedFromMustGet := base64.StdEncoding.EncodeToString(result.MethodResults[2*i+1].RawReturnValue)
		if abiHashedOutputB64 != b64ReturnedFromGet {
			return fmt.Errorf("outputs don't match for round %d TXID %s %s != %s", r, result.TxIDs[2*i+0], b64ReturnedFromGet, abiHashedOutputB64)
		}
		if abiHashedOutputB64 != b64ReturnedFromMustGet {
			return fmt.Errorf("outputs don't match for round %d TXID %s %s != %s", r, result.TxIDs[2*i+1], b64ReturnedFromGet, abiHashedOutputB64)
		}
	}

	return nil

}

func getMainGlobalStateSlot(appID uint64, algodClient *algod.Client) (string, error) {
	appRes, err := algodClient.GetApplicationByID(appID).Do(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed getting app info for appID %d", appID)
	}
	for _, kv := range appRes.Params.GlobalState {
		if kv.Key == "" {
			return kv.Value.Bytes, nil
		}
	}
	return "", fmt.Errorf("can't find main slot for appID %d", appID)
}

func testFailedSubmit(round, latestBlockRound uint64, vrfPrivateKey ed25519.PrivateKey, serviceAccount crypto.Account, appID,
	dummyAppID uint64, algodClient *algod.Client, suggestedParams types.SuggestedParams, errMsg string) error {
	//suggestedParams.LastRoundValid = types.Round(min(round, latestBlockRound)) + 1
	//suggestedParams.FirstRoundValid = suggestedParams.LastRoundValid - 1000

	suggestedParams.FirstRoundValid = types.Round(latestBlockRound)
	suggestedParams.LastRoundValid = suggestedParams.FirstRoundValid + 1
	err := handleCurrentRound(round, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, suggestedParams, nil)
	if err == nil || !strings.Contains(err.Error(), errMsg) {
		return fmt.Errorf("error in handleCurrentRound for round %d: expected err == %s got err == %v", round, errMsg, err)
	}
	return nil
}

func runSomeTests(round, appID, dummyAppID uint64, serviceAccount crypto.Account, algodClient *algod.Client,
	vrfPrivateKey ed25519.PrivateKey) error {

	sp, err := GetSuggestedParams(algodClient)
	if err != nil {
		return fmt.Errorf("failed getting suggestedParams from algod")
	}

	log.Debugf("testing that round was submitted with 'get' method")
	getUserData := getRandomUserData()
	vrfOutput := getVrfOutputForRound(round)
	getResult, err := testVrfSubmitted(round, appID, serviceAccount, vrfOutput, getUserData, sp, algodClient, "get")
	if err != nil {
		return fmt.Errorf("error getting VRF from smart contract: %v", err)
	}
	log.Debugf("testing that round was submitted with 'must_get' method")
	mustGetUserData := getRandomUserData()
	mustGetResult, err := testVrfSubmitted(round, appID, serviceAccount, vrfOutput, mustGetUserData, sp, algodClient, "must_get")
	if err != nil {
		return fmt.Errorf("error getting VRF from smart contract: %v", err)
	}
	res, ok := resultsHistory[getResult]
	if ok {
		return fmt.Errorf("random value from 'get' already seen in round %d with user_data %v and method %s", res.Round, res.UserData, res.Method)
	}
	resultsHistory[getResult] = Result{
		Round:    round,
		UserData: getUserData,
		Method:   "get",
	}
	res, ok = resultsHistory[mustGetResult]
	if ok {
		return fmt.Errorf("random value from 'must_get' already seen in round %d with user_data %v and method %s", res.Round, res.UserData, res.Method)
	}
	resultsHistory[mustGetResult] = Result{
		Round:    round,
		UserData: mustGetUserData,
		Method:   "must_get",
	}
	// this must always succeed, even when last_round_stored - first_round stored is higher than 1512 (NbStoredVrfOutputs*VrfRoundMultiple)
	// the SC stores VRF outputs for the last 1512 rounds.
	// since the last VRF output submitted was for block number `round`, round - 1512 is out of range of the values stored
	log.Debugf("testing 'must_get' with round lower than range")
	err = testGetOrMustGetFail(round-NbStoredVrfOutputs*VrfRoundMultiple, appID, serviceAccount, sp, algodClient, "must_get")
	if err != nil {
		return fmt.Errorf("error testMustGetFail: %v", err)
	}
	// this must always succeed, even when last_round_stored - first_round stored is higher than 1512
	log.Debugf("testing 'get' with round lower than range")
	err = testGetOrMustGetFail(round-NbStoredVrfOutputs*VrfRoundMultiple, appID, serviceAccount, sp, algodClient, "get")
	if err != nil {
		return fmt.Errorf("error testGetFail: %v", err)
	}
	log.Debugf("testing 'must_get' with round higher than range")
	err = testGetOrMustGetFail(round+1, appID, serviceAccount, sp, algodClient, "must_get")
	if err != nil {
		return fmt.Errorf("error testMustGetFail: %v", err)
	}
	log.Debugf("testing 'get' with round higher than range")
	err = testGetOrMustGetFail(round+1, appID, serviceAccount, sp, algodClient, "get")
	if err != nil {
		return fmt.Errorf("error testGetFail: %v", err)
	}
	if round >= startingRound+VrfRoundMultiple {
		log.Debugf("testing rounds that are not multiple of 8")
		err = testNonMultipleOf8Rounds(round, appID, serviceAccount, vrfOutput, sp, algodClient)
		if err != nil {
			return fmt.Errorf("error testNonMultipleOf8Rounds: %v", err)
		}
	}
	if round >= startingRound+(NbStoredVrfOutputs-1)*VrfRoundMultiple {
		// testing we can get the oldest VRF output in global storage
		mainSlotB64, err := getMainGlobalStateSlot(appID, algodClient)
		if err != nil {
			return fmt.Errorf("error getting main slot: %v", err)
		}
		mainSlot, err := base64.StdEncoding.DecodeString(mainSlotB64)
		if err != nil {
			return fmt.Errorf("error decoding main slot: %v", err)
		}
		firstStoredRound := binary.BigEndian.Uint64(mainSlot[8:16])
		// the SC stores VRF outputs for the last 1512 (NbStoredVrfOutputs*VrfRoundMultiple) rounds,
		// and since the last VRF output submitted was for block number `round`,
		// `round - (NbStoredVrfOutputs - 1) * VrfRoundMultiple` is the first value in range of the values stored
		oldestStoredVrfRound := round - (NbStoredVrfOutputs-1)*VrfRoundMultiple
		if firstStoredRound != oldestStoredVrfRound {
			return fmt.Errorf("firstStoredRound %d != %d oldestStoredVrfRound", firstStoredRound, oldestStoredVrfRound)
		}
		oldestStoredVrfOutput := getVrfOutputForRound(oldestStoredVrfRound)
		log.Debugf("testing getting VRF output long after it was submitted with 'get'")
		_, err = testVrfSubmitted(oldestStoredVrfRound, appID, serviceAccount, oldestStoredVrfOutput, getUserData, sp, algodClient, "get")
		if err != nil {
			return fmt.Errorf("error getting VRF from smart contract: %v", err)
		}
		log.Debugf("testing getting VRF output long after it was submitted with 'must_get'")
		_, err = testVrfSubmitted(oldestStoredVrfRound, appID, serviceAccount, oldestStoredVrfOutput, mustGetUserData, sp, algodClient, "must_get")
		if err != nil {
			return fmt.Errorf("error getting VRF from smart contract: %v", err)
		}
	}

	latestRound, err := getLatestRound(algodClient)
	if err != nil {
		return fmt.Errorf("failed to get status from algod")
	}
	nextRound := latestRound + 1 // assuming testing on sandnet

	errMsgInvalidRange := "logic eval error: assert failed pc=693. Details: pc=693, opcodes=callsub label23\\n||\\nassert\\n"
	errMsgInvalidProof := "logic eval error: assert failed pc=386. Details: pc=386, opcodes=intc_2 // 1\\n==\\nassert\\n"
	errMsgOverflow := "logic eval error: + overflowed. Details: pc=629, opcodes=load 43\\npushint 1000\\n+\\n"

	err = testFailedSubmit(math.MaxUint64, latestRound, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, sp, errMsgOverflow)
	if err != nil {
		return fmt.Errorf("failed overflow testFailedSubmit %v", err)
	}
	log.Debugf("testing submitting not subsequent rounds")
	for i := 2; i <= 125; i++ {
		futureRound := round + uint64(i)*VrfRoundMultiple
		if futureRound+NbRetainedBlocks > nextRound+NbGraceBlocks {
			err = testFailedSubmit(futureRound, latestRound, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, sp, errMsgInvalidRange)
			if err != nil {
				return fmt.Errorf("failed testFailedSubmit %v futureRound %d", err, futureRound)
			}
		}
	}
	log.Debugf("nextRound %d", nextRound)
	for i := 1; i <= 125; i++ {
		flooredLatestRound := floorToMultipleOfX(latestRound, VrfRoundMultiple)
		pastRound := flooredLatestRound - uint64(i)*VrfRoundMultiple
		if flooredLatestRound > uint64(i)*VrfRoundMultiple && pastRound > round+8 {
			if pastRound+NbRetainedBlocks > nextRound+NbGraceBlocks {
				err = testFailedSubmit(pastRound, latestRound, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, sp, errMsgInvalidRange)
				if err != nil {
					return fmt.Errorf("failed testFailedSubmit %v pastRound %d", err, pastRound)
				}
			} else {
				err = testFailedSubmit(pastRound, latestRound, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, sp, errMsgInvalidProof)
				if err != nil {
					return fmt.Errorf("failed testFailedSubmit %v pastRound %d", err, pastRound)
				}
			}
		}
	}

	return nil
}

func testGetOrMustGetFail(round, appID uint64, serviceAccount crypto.Account, sp types.SuggestedParams,
	algodClient *algod.Client, methodName string) error {
	var atc future.AtomicTransactionComposer
	err := addGetOrMustGetMethodCall(&atc, round, appID, serviceAccount, sp, []byte{}, methodName)
	if err != nil {
		return fmt.Errorf("error in addGetMethodCall for round %d: %v", round, err)
	}
	result, err := atc.Execute(algodClient, context.Background(), 3)
	if methodName == "get" {
		if err != nil {
			return fmt.Errorf("error in atc.Execute for round %d: %v", round, err)
		}
		if len(result.MethodResults) < 1 {
			return fmt.Errorf("didn't get MethodResults for round %d", round)
		}
		b64Returned := base64.StdEncoding.EncodeToString(result.MethodResults[0].RawReturnValue)
		expected := "AAA="
		if b64Returned != expected {
			return fmt.Errorf("expected response to be %s, got %s", expected, b64Returned)
		}
	} else {
		//log.Debugf("err is %v", err)
		if err == nil || !strings.Contains(err.Error(), "logic eval error: assert failed pc=862. Details: pc=862, opcodes=load 14\\ncallsub label26\\nassert\\n") {
			return fmt.Errorf("error in atc.Execute for round %d: expected failure got err == %v", round, err)
		}
	}
	return nil
}

func testVrfSubmitted(round, appID uint64, serviceAccount crypto.Account, vrfOutput, userData []byte, sp types.SuggestedParams,
	algodClient *algod.Client, methodName string) (string, error) {
	var atc future.AtomicTransactionComposer
	err := addGetOrMustGetMethodCall(&atc, round, appID, serviceAccount, sp, userData, methodName)
	if err != nil {
		return "", fmt.Errorf("error in addGetOrMustGetMethodCall for round %d: %v", round, err)
	}
	result, err := atc.Execute(algodClient, context.Background(), 3)
	if err != nil {
		return "", fmt.Errorf("error in atc.Execute for round %d: %v", round, err)
	}
	if len(result.MethodResults) < 1 {
		return "", fmt.Errorf("didn't get MethodResults for round %d", round)
	}

	// Verify the random output matches what it should be
	roundBytes := convertUint64ToBigEndianBytes(round)
	storedVRFOutput := vrfOutput[:StoredVrfOutputLen] // we truncate the VRF output to StoredVrfOutputLen bytes

	//log.Debugf("stored VRF output should be: %v", base64.StdEncoding.EncodeToString(storedVRFOutput))

	hashedOutput := sha3.Sum256(append(storedVRFOutput[:], append(roundBytes, userData...)...))
	// ABI adds 0x0020 at the beginning, as it's the length of the output
	abiHashedOutputB64 := base64.StdEncoding.EncodeToString(append([]byte{0x00, 0x20}, hashedOutput[:]...))
	//log.Debugf("hashed output (b64) for round %d is %v", round, abiHashedOutputB64)

	b64Returned := base64.StdEncoding.EncodeToString(result.MethodResults[0].RawReturnValue)
	if abiHashedOutputB64 != b64Returned {
		return "", fmt.Errorf("outputs don't match for round %d TXID %s %s != %s", round, result.TxIDs[0], b64Returned, abiHashedOutputB64)
	}
	//log.Debugf("passed tests: ABI hashed output (b64) for round %d is %v", round, abiHashedOutputB64)
	return b64Returned, nil
}

// generates a group of 3 application calls:
// the 1st App call is to the smart-contract to respond the VRF output, while the 2nd and 3rd are dummy app calls used
// to increase the cost pool.
func buildAnswerPhaseTransactionsGroupABI(appID, dummyAppID, round uint64, serviceAccount crypto.Account,
	vrfProof []byte, sp types.SuggestedParams) ([]byte, error) {

	var atc future.AtomicTransactionComposer
	signer := future.BasicAccountTransactionSigner{Account: serviceAccount}
	methodSig := "submit(uint64,byte[80])void"
	method, err := abi.MethodFromSignature(methodSig)
	if err != nil {
		return nil, fmt.Errorf("error abi.MethodFromSignature(methodSig) %v", err)
	}
	//sp.FirstRoundValid = types.Round(round + 1)
	//sp.LastRoundValid = sp.FirstRoundValid + 1000
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
func handleCurrentRound(currentRoundHandled uint64, vrfPrivateKey ed25519.PrivateKey, serviceAccount crypto.Account, appID, dummyAppID uint64, algodClient *algod.Client, suggestedParams types.SuggestedParams, blockSeed []byte) error {
	blockNumberBytes := convertUint64ToBigEndianBytes(currentRoundHandled)
	vrfOutput, vrfProof, err := computeAndSignVrf(
		blockNumberBytes,
		blockSeed,
		vrfPrivateKey,
	)
	if err != nil {
		return fmt.Errorf("failed computing vrf for %d: %v", currentRoundHandled, err)
	}

	stxBytes, err := buildAnswerPhaseTransactionsGroupABI(
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
	txId, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return fmt.Errorf(
			"failed sending transactions group for %d: %v",
			currentRoundHandled,
			err,
		)
		//log.Debugf("stxbytes bas64: %v", base64.StdEncoding.EncodeToString(stxBytes))
	}
	vrfOutputsHistory = append(vrfOutputsHistory, vrfOutput)
	log.Infof("Sent transaction %s\n########################################################", txId)
	return nil
}

// getting suggested params with exponential back-off
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

func sendDummyTxn(algodClient *algod.Client, serviceAccount crypto.Account, suggestedParams types.SuggestedParams) {
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

func CreateDummyApp(approvalProgram, clearProgram []byte, appCreatorSK ed25519.PrivateKey, algodClient *algod.Client,
	suggestedParams types.SuggestedParams) (uint64, error) {
	stxBytes, err := generateSignedDummyAppCreate(approvalProgram, clearProgram, types.StateSchema{},
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

func CreateABIApp(startingRound, dummyAppID uint64, algodClient *algod.Client, vrfPublicKey ed25519.PublicKey, appCreatorPrivateKey ed25519.PrivateKey,
	vrfProof, approvalBytes, clearBytes []byte, suggestedParams types.SuggestedParams) (
	uint64, error) {
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

func createABIAppWithVRFKey(startingRound, dummyAppID uint64, algodClient *algod.Client, vrfPrivateKey,
	appCreatorPrivateKey ed25519.PrivateKey, approvalBytes, clearBytes []byte, suggestedParams types.SuggestedParams) (
	uint64, error) {

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
	vrfOutputsHistory = append(vrfOutputsHistory, vrfOutput)
	return CreateABIApp(startingRound, dummyAppID, algodClient, vrfPrivateKey.Public().(ed25519.PublicKey),
		appCreatorPrivateKey, vrfProof, approvalBytes, clearBytes, suggestedParams)
}

func CompileTeal(approvalProgramFilename, clearProgramFilename string, algodClient *algod.Client) ([]byte, []byte, error) {
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

func floorToMultipleOfX(num, x uint64) uint64 {
	return (num / x) * x
}

func ceilingToMultipleOfX(num, x uint64) uint64 {
	return ((num + x - 1) / x) * x
}

func mainLoop(appID, dummyAppID uint64, algodClient *algod.Client,
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
			if currentRoundHandled%VrfRoundMultiple != 0 {
				sendDummyTxn(algodClient, serviceAccount, suggestedParams)
			}
			sleepTime := time.Duration(WaitBetweenBlocksMS) * time.Millisecond
			//log.Debugf("sleeping %v", sleepTime)
			time.Sleep(sleepTime)
		}
		nextBlockRound := latestBlockRound + 1 // assuming we're testing on sandnet
		//log.Debugf("last round %d current round %d", latestBlockRound, currentRoundHandled)
		// check if we are in recovery
		// we can only get the block seed of rounds [latestBlockRound - NbRetainedBlocks, latestBlockRound], thus we enter recovery
		// if we currently handle rounds that are < latestBlockRound - NbRetainedBlocks
		if currentRoundHandled%VrfRoundMultiple == 0 && latestBlockRound > currentRoundHandled+NbRetainedBlocks {
			currentRoundHandled = floorToMultipleOfX(nextBlockRound-NbRetainedBlocks+VrfRoundMultiple, VrfRoundMultiple)
			// starting round is a global variable, we set it here mainly to support tests
			startingRound = currentRoundHandled
			vrfOutputsHistory = [][]byte{}
			isRecovering = true
			log.Infof("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ starting recovery from round %d", currentRoundHandled)
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
			err = handleCurrentRound(currentRoundHandled, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, suggestedParams, block.Seed[:])
			if err != nil {
				log.Errorf("error handling requests for current round %d: %v", currentRoundHandled, err)
				return
			}
			if !isRecovering {
				err = runSomeTests(currentRoundHandled, appID, dummyAppID, serviceAccount, algodClient, vrfPrivateKey)
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
		// dirty workaround for weird issue where no blocks are added if no transactions
		for i := 0; i < 13; i++ {
			sendDummyTxn(algodClient, serviceAccount, suggestedParams)
		}

		log.Info("creating dummy app...")
		dummyApprovalBytes, dummyClearBytes, err := CompileTeal(dummyAppApprovalFilename, dummyAppClearFilename, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		dummyAppID, err := CreateDummyApp(dummyApprovalBytes, dummyClearBytes, appCreatorPrivateKey, algodClient,
			suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("dummy app id: %d\n", dummyAppID)
		log.Info("creating ABI app...")
		approvalBytes, clearBytes, err := CompileTeal(approvalProgramFilename, clearProgramFilename, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		appID, err := createABIAppWithVRFKey(
			startingRound, dummyAppID, algodClient, vrfPrivateKey,
			appCreatorPrivateKey, approvalBytes, clearBytes, suggestedParams)
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
			algodClient,
			vrfPrivateKey,
			serviceAccount,
		)
		//cmd.HelpFunc()(cmd, args)
	},
}
