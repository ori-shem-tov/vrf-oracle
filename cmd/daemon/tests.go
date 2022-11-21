package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/algorand/go-algorand-sdk/abi"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"math"
	"strings"
)

func runSomeTests(lastSubmittedRound, appID, dummyAppID, startingRound uint64, serviceAccount crypto.Account, algodClient *algod.Client,
	vrfPrivateKey ed25519.PrivateKey) error {

	sp, err := GetSuggestedParams(algodClient)
	if err != nil {
		return fmt.Errorf("failed getting suggestedParams from algod")
	}

	log.Debugf("testing that lastSubmittedRound was submitted with 'get' method")
	getUserData := getRandomUserData()
	vrfOutput := getVrfOutputForRound(lastSubmittedRound, startingRound)
	getResult, err := testGetOrMustGetSucceed(lastSubmittedRound, appID, serviceAccount, vrfOutput, getUserData, sp, algodClient, "get")
	if err != nil {
		return fmt.Errorf("error getting VRF from smart contract: %v", err)
	}
	log.Debugf("testing that lastSubmittedRound was submitted with 'must_get' method")
	mustGetUserData := getRandomUserData()
	mustGetResult, err := testGetOrMustGetSucceed(lastSubmittedRound, appID, serviceAccount, vrfOutput, mustGetUserData, sp, algodClient, "must_get")
	if err != nil {
		return fmt.Errorf("error getting VRF from smart contract: %v", err)
	}
	res, ok := resultsHistory[getResult]
	if ok {
		return fmt.Errorf("random value from 'get' already seen in round %d with user_data %v and method %s", res.Round, res.UserData, res.Method)
	}
	resultsHistory[getResult] = Result{
		Round:    lastSubmittedRound,
		UserData: getUserData,
		Method:   "get",
	}
	res, ok = resultsHistory[mustGetResult]
	if ok {
		return fmt.Errorf("random value from 'must_get' already seen in round %d with user_data %v and method %s", res.Round, res.UserData, res.Method)
	}
	resultsHistory[mustGetResult] = Result{
		Round:    lastSubmittedRound,
		UserData: mustGetUserData,
		Method:   "must_get",
	}
	// this must always succeed, even when last_round_stored - first_round stored is higher than 1512 (NbStoredVrfOutputs*VrfRoundMultiple)
	// the SC stores VRF outputs for the last 1512 rounds.
	// since the last VRF output submitted was for block number `lastSubmittedRound`, lastSubmittedRound - 1512 is out of range of the values stored
	log.Debugf("testing 'must_get' with round lower than range")
	err = testGetOrMustGetFail(lastSubmittedRound-NbStoredVrfOutputs*VrfRoundMultiple, appID, serviceAccount, sp, algodClient, "must_get")
	if err != nil {
		return fmt.Errorf("error testMustGetFail: %v", err)
	}
	// this must always succeed, even when last_round_stored - first_round stored is higher than 1512
	log.Debugf("testing 'get' with round lower than range")
	err = testGetOrMustGetFail(lastSubmittedRound-NbStoredVrfOutputs*VrfRoundMultiple, appID, serviceAccount, sp, algodClient, "get")
	if err != nil {
		return fmt.Errorf("error testGetFail: %v", err)
	}
	log.Debugf("testing 'must_get' with round higher than range")
	err = testGetOrMustGetFail(lastSubmittedRound+1, appID, serviceAccount, sp, algodClient, "must_get")
	if err != nil {
		return fmt.Errorf("error testMustGetFail: %v", err)
	}
	log.Debugf("testing 'get' with round higher than range")
	err = testGetOrMustGetFail(lastSubmittedRound+1, appID, serviceAccount, sp, algodClient, "get")
	if err != nil {
		return fmt.Errorf("error testGetFail: %v", err)
	}
	if lastSubmittedRound >= startingRound+VrfRoundMultiple {
		log.Debugf("testing rounds that are not multiple of 8")
		err = testNonMultipleOf8Rounds(lastSubmittedRound, appID, serviceAccount, vrfOutput, sp, algodClient)
		if err != nil {
			return fmt.Errorf("error testNonMultipleOf8Rounds: %v", err)
		}
	}
	if lastSubmittedRound >= startingRound+(NbStoredVrfOutputs-1)*VrfRoundMultiple {
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
		// and since the last VRF output submitted was for block number `lastSubmittedRound`,
		// `lastSubmittedRound - (NbStoredVrfOutputs - 1) * VrfRoundMultiple` is the first value in range of the values stored
		oldestStoredVrfRound := lastSubmittedRound - (NbStoredVrfOutputs-1)*VrfRoundMultiple
		if firstStoredRound != oldestStoredVrfRound {
			return fmt.Errorf("firstStoredRound %d != %d oldestStoredVrfRound", firstStoredRound, oldestStoredVrfRound)
		}
		oldestStoredVrfOutput := getVrfOutputForRound(oldestStoredVrfRound, startingRound)
		log.Debugf("testing getting VRF output long after it was submitted with 'get'")
		_, err = testGetOrMustGetSucceed(oldestStoredVrfRound, appID, serviceAccount, oldestStoredVrfOutput, getUserData, sp, algodClient, "get")
		if err != nil {
			return fmt.Errorf("error getting VRF from smart contract: %v", err)
		}
		log.Debugf("testing getting VRF output long after it was submitted with 'must_get'")
		_, err = testGetOrMustGetSucceed(oldestStoredVrfRound, appID, serviceAccount, oldestStoredVrfOutput, mustGetUserData, sp, algodClient, "must_get")
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
	errMsgInvalidVRFProof := "logic eval error: assert failed pc=386. Details: pc=386, opcodes=intc_2 // 1\\n==\\nassert\\n"
	errMsgOverflow := "logic eval error: + overflowed. Details: pc=629, opcodes=load 43\\npushint 1000\\n+\\n"

	err = testFailedSubmit(math.MaxUint64, latestRound, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, sp, errMsgOverflow)
	if err != nil {
		return fmt.Errorf("failed overflow testFailedSubmit %v", err)
	}
	log.Debugf("testing submitting not subsequent rounds")
	for i := 2; i <= 125; i++ {
		futureRound := lastSubmittedRound + uint64(i)*VrfRoundMultiple
		if futureRound+NbRetainedBlocks > nextRound+NbGraceBlocks {
			err = testFailedSubmit(futureRound, latestRound, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, sp, errMsgInvalidRange)
			if err != nil {
				return fmt.Errorf("failed testFailedSubmit %v futureRound %d", err, futureRound)
			}
		}
	}
	log.Debugf("nextRound %d", nextRound)
	flooredLatestRound := floorToMultipleOfX(latestRound, VrfRoundMultiple)
	for i := 1; i <= 125; i++ {
		pastRound := flooredLatestRound - uint64(i)*VrfRoundMultiple
		if flooredLatestRound > uint64(i)*VrfRoundMultiple && pastRound > lastSubmittedRound+VrfRoundMultiple {
			if pastRound+NbRetainedBlocks > nextRound+NbGraceBlocks {
				// in the case, the smart contract is not in recovery mode so the expected error would be that the
				// round is out of range
				err = testFailedSubmit(pastRound, latestRound, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, sp, errMsgInvalidRange)
				if err != nil {
					return fmt.Errorf("failed testFailedSubmit %v pastRound %d", err, pastRound)
				}
			} else {
				// in the case, the smart contract is in recovery mode so the expected error would be that the
				// VRF proof is invalid since we don't submit the actual proof that matches the given round
				err = testFailedSubmit(pastRound, latestRound, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, sp, errMsgInvalidVRFProof)
				if err != nil {
					return fmt.Errorf("failed testFailedSubmit %v pastRound %d", err, pastRound)
				}
			}
		}
	}

	return nil
}

// getRandomUserData generates a 10 byte pseudorandom slice
func getRandomUserData() []byte {
	res := make([]byte, 10)
	_, err := rand.Read(res)
	if err != nil {
		panic(err)
	}
	return res
}

// getVrfOutputForRound gets the VRF output for the given round stored in the global map vrfOutputsHistory
func getVrfOutputForRound(round, startingRound uint64) []byte {
	return vrfOutputsHistory[(round-startingRound)/VrfRoundMultiple]
}

// testNonMultipleOf8Rounds tests getting VRF outputs from the smart contract with rounds that are not multiples of 8
func testNonMultipleOf8Rounds(lastSubmittedRound, appID uint64, serviceAccount crypto.Account, vrfOutput []byte, sp types.SuggestedParams,
	algodClient *algod.Client) error {

	var atc future.AtomicTransactionComposer
	for i := 0; i < 7; i++ {
		r := uint64(i) + lastSubmittedRound - 7
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
		return fmt.Errorf("error in atc.Execute for lastSubmittedRound %d: %v", lastSubmittedRound, err)
	}
	if len(result.MethodResults) != 7*2 {
		return fmt.Errorf("didn't get enough MethodResults for lastSubmittedRound %d", lastSubmittedRound)
	}

	storedVRFOutput := vrfOutput[:StoredVrfOutputLen] // we truncate the VRF output to StoredVrfOutputLen bytes

	for i := 0; i < 7; i++ {
		r := uint64(i) + lastSubmittedRound - 7
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
			return fmt.Errorf("outputs don't match for round %d TXID %s %s != %s", r, result.TxIDs[2*i+1], b64ReturnedFromMustGet, abiHashedOutputB64)
		}
	}

	return nil

}

// getMainGlobalStateSlot get the main slot from the smart contract's global state.
// The value stored in this slot is `last_round|first_round|public_key` where the `|` is the concatenation operator
// and `last_round` and `first_round` are encoded as 8 bytes in big endian.
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

// testFailedSubmit tests that submitting a VRF proof for a round that should not be expected by the smart contract fails
func testFailedSubmit(round, latestBlockRound uint64, vrfPrivateKey ed25519.PrivateKey, serviceAccount crypto.Account, appID,
	dummyAppID uint64, algodClient *algod.Client, suggestedParams types.SuggestedParams, errMsg string) error {

	suggestedParams.FirstRoundValid = types.Round(latestBlockRound)
	suggestedParams.LastRoundValid = suggestedParams.FirstRoundValid + 1
	err := handleCurrentRound(round, vrfPrivateKey, serviceAccount, appID, dummyAppID, algodClient, suggestedParams, nil)
	if err == nil || !strings.Contains(err.Error(), errMsg) {
		return fmt.Errorf("error in handleCurrentRound for round %d: expected err == %s got err == %v", round, errMsg, err)
	}
	return nil
}

// testGetOrMustGetFail tests cases where the smart contract has no VRF output stored for a given round
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

// testGetOrMustGetSucceed tests cases where the smart contract has a VRF output stored for a given round
func testGetOrMustGetSucceed(round, appID uint64, serviceAccount crypto.Account, vrfOutput, userData []byte, sp types.SuggestedParams,
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

// addGetOrMustGetMethodCall add a 'get' or 'must_get' method call to atc
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
