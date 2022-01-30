package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	libsodium_wrapper "github.com/ori-shem-tov/vrf-oracle/libsodium-wrapper"
	log "github.com/sirupsen/logrus"
)

var (
	numOfDummyTxns = 4
	dummyAppBytes  = []byte{0x05, 0x81, 0x01} // pragma 5; pushint 1;
)

type VRFDaemon struct {
	AlgodClient *algod.Client // Client used to interact with the chain

	DummyAppID  uint64        // Dummy app used to increase budget
	AppID       uint64        // Application that validates and stores randomness
	AppHashAddr types.Address // Hash of application approval program, needed to produce ed25519 bytes to verify

	CurrentRound uint64 // The latest round we've sesen

	Signer         crypto.Account
	VRF            crypto.Account
	AppCreator     crypto.Account
	ServiceAccount crypto.Account
}

func (v *VRFDaemon) CreateApplications() error {
	log.Info("creating dummy app...")

	dummyAppID, err := v.createDummyApp()
	if err != nil {
		return fmt.Errorf("failed to create dummy app: %+v", err)
	}
	v.DummyAppID = dummyAppID

	log.Info("creating oracle app")

	appIdx, err := v.createOracleApp()
	if err != nil {
		return fmt.Errorf("failed to create oracle app: %+v", err)
	}
	v.AppID = appIdx

	return nil
}

func (v *VRFDaemon) Start() {
	v.CurrentRound += writeBlockInterval

	for {
		sleepTime := time.Duration(waitBetweenBlocksMS) * time.Millisecond
		log.Debugf("sleeping %v", sleepTime)

		time.Sleep(sleepTime)

		log.Infof("getting block seed for %d", v.CurrentRound)
		block, err := getBlock(v.AlgodClient, v.CurrentRound)
		if err != nil {
			log.Errorf("error getting block seed of block %d from algod", v.CurrentRound)
			return
		}

		if block.Round <= types.Round(v.CurrentRound) {
			// We already saw this
			continue
		}

		if uint64(block.Round)%writeBlockInterval != 0 {
			// We only want to write on the interval specified
			continue
		}

		if err := v.HandleBlock(block); err != nil {
			log.Warnf("Failed to handle request: %+v", err)
			continue
		}

		// Update our last seen round
		v.CurrentRound = uint64(block.Round)
	}
}

// handles requests for the current round: computes the VRF output and sends it to the smart-contract
func (v *VRFDaemon) HandleBlock(block types.Block) error {

	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, uint64(block.Round))

	blockSeed := block.BlockHeader.Seed[:]

	signedVrfOutput, vrfOutput, err := v.ComputeAndSignVRFForRound(block)
	if err != nil {
		return fmt.Errorf("failed to compute and sign vrf: %+v", err)
	}

	sp, err := v.AlgodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %+v", err)
	}

	// generates a group of N application calls:
	// the 1st App call is to the smart-contract to respond the VRF output, while the rest are
	// dummy app calls used to increase the budget
	appArgs := [][]byte{
		[]byte("respond"), blockNumberBytes, blockSeed, vrfOutput, signedVrfOutput[:],
	}

	appCall, err := future.MakeApplicationNoOpTx(
		v.AppID, appArgs, nil, nil, nil, sp, v.ServiceAccount.Address, nil, types.Digest{}, [32]byte{}, types.Address{},
	)
	if err != nil {
		return fmt.Errorf("failed creating app call: %v", err)
	}

	appCall.Fee *= types.MicroAlgos(1 + numOfDummyTxns)
	appCalls := []types.Transaction{appCall}
	for i := 0; i < numOfDummyTxns; i++ {
		dummyAppCall, err := future.MakeApplicationNoOpTx(
			v.DummyAppID, nil, nil, nil, nil, sp, v.ServiceAccount.Address,
			[]byte{byte(i)}, types.Digest{}, [32]byte{}, types.ZeroAddress,
		)
		if err != nil {
			return fmt.Errorf("failed creating dummy app call: %v", err)
		}

		dummyAppCall.Fee = 0

		appCalls = append(appCalls, dummyAppCall)
	}

	grouped, err := transaction.AssignGroupID(appCalls, "")
	if err != nil {
		return fmt.Errorf("failed grouping transactions: %v", err)
	}

	var signedGroup []byte
	for _, txn := range grouped {
		_, signed, err := crypto.SignTransaction(v.ServiceAccount.PrivateKey, txn)
		if err != nil {
			return fmt.Errorf("failed signing app call: %v", err)
		}
		signedGroup = append(signedGroup, signed...)
	}

	txid, err := v.AlgodClient.SendRawTransaction(signedGroup).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed sending transactions group for %v: %v", block.Round, err)
	}

	log.Infof("Sent request txn: %s", txid)

	return nil
}

// compute the VRF output and sign the concatenation of the input with the output (to be verified by the smart contract)
func (v *VRFDaemon) ComputeAndSignVRFForRound(block types.Block) (types.Signature, []byte, error) {

	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, uint64(block.Round))
	vrfInput := sha512.Sum512_256(append(blockNumberBytes, block.BlockHeader.Seed[:]...))

	proof, ok := getVrfPrivateKey(v.VRF.PrivateKey).ProveBytes(vrfInput[:])
	if !ok {
		return types.Signature{}, []byte{}, fmt.Errorf("error computing vrf proof")
	}

	vrfOutput, ok := proof.Hash()
	if !ok {
		return types.Signature{}, []byte{}, fmt.Errorf("error computing vrf output")
	}

	toSign := append(append(blockNumberBytes, block.BlockHeader.Seed[:]...), vrfOutput[:]...)
	sig, err := crypto.TealSign(v.VRF.PrivateKey, toSign, v.AppHashAddr)
	if err != nil {
		return types.Signature{}, []byte{}, fmt.Errorf("error signing vrf output")
	}

	return sig, vrfOutput[:], nil
}

// createOracleApp creates the application that validates the input and provides an interface
// to retrieve the randomness results
func (v *VRFDaemon) createOracleApp() (uint64, error) {
	sp, err := v.AlgodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to get suggested params: %+v", err)
	}

	approvalBytes, clearBytes, err := compileTeal(v.AlgodClient, approvalProgramFilename, clearProgramFilename)
	if err != nil {
		return 0, fmt.Errorf("failed to compile teal: %+v", err)
	}
	v.AppHashAddr = crypto.AddressFromProgram(approvalBytes)

	block, err := getBlock(v.AlgodClient, v.CurrentRound)
	if err != nil {
		return 0, fmt.Errorf("failed to get block seed of block %d from algod", v.CurrentRound)
	}

	signedVrfOutput, vrfOutput, err := v.ComputeAndSignVRFForRound(block)
	if err != nil {
		return 0, fmt.Errorf("failed to compute vrf for %d: %v", v.CurrentRound, err)
	}

	globalStateSchema := types.StateSchema{NumUint: 0, NumByteSlice: 64}
	localStateSchema := types.StateSchema{NumUint: 0, NumByteSlice: 0}

	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, v.CurrentRound)
	args := [][]byte{
		blockNumberBytes, v.Signer.PrivateKey[32:], v.VRF.PrivateKey[32:],
		block.BlockHeader.Seed[:], vrfOutput, signedVrfOutput[:],
	}

	appCall, err := future.MakeApplicationCreateTx(
		false, approvalBytes, clearBytes, globalStateSchema, localStateSchema, args,
		nil, nil, nil, sp, v.AppCreator.Address, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to make app create txn: %+v", err)
	}

	appCalls := []types.Transaction{appCall}
	for i := 0; i < 4; i++ {
		dummyAppCall, err := future.MakeApplicationNoOpTx(
			v.DummyAppID, nil, nil, nil, nil, sp, v.AppCreator.Address,
			[]byte{byte(i)}, types.Digest{}, [32]byte{}, types.ZeroAddress,
		)
		if err != nil {
			return 0, fmt.Errorf("failed creating dummy app call: %v", err)
		}
		appCalls = append(appCalls, dummyAppCall)
	}

	grouped, err := transaction.AssignGroupID(appCalls, "")
	if err != nil {
		return 0, fmt.Errorf("failed grouping transactions: %v", err)
	}

	var signedGroup []byte
	for _, txn := range grouped {
		_, signed, err := crypto.SignTransaction(v.AppCreator.PrivateKey, txn)
		if err != nil {
			return 0, fmt.Errorf("failed signing app call: %v", err)
		}
		signedGroup = append(signedGroup, signed...)
	}

	txID, err := v.AlgodClient.SendRawTransaction(signedGroup).Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed sending app create transaction: %v", err)
	}

	res, err := future.WaitForConfirmation(v.AlgodClient, txID, 2, context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed while waiting for app create to be confirmed: %+v", err)
	}

	return res.ApplicationIndex, nil
}

// createDummyApp creates an application whose sole purpose is to allow us to increase
// our opcode budget by making multiple grouped application call transactions
func (v *VRFDaemon) createDummyApp() (uint64, error) {
	sp, err := v.AlgodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to get suggested params: %+v", err)
	}

	schema := types.StateSchema{}
	tx, err := future.MakeApplicationCreateTx(
		false, dummyAppBytes, dummyAppBytes, schema, schema,
		nil, nil, nil, nil, sp, v.AppCreator.Address, nil,
		types.Digest{}, [32]byte{}, types.ZeroAddress,
	)
	if err != nil {
		return 0, err
	}

	_, stxBytes, err := crypto.SignTransaction(v.AppCreator.PrivateKey, tx)
	if err != nil {
		return 0, err
	}

	txID, err := v.AlgodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed sending app call: %v", err)
	}

	res, err := future.WaitForConfirmation(v.AlgodClient, txID, 2, context.Background())
	if err != nil {
		return 0, err
	}

	return res.ApplicationIndex, nil
}

func compileTeal(algodClient *algod.Client, approvalProgramFilename, clearProgramFilename string) ([]byte, []byte, error) {
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

func getStartingRound(algodClient *algod.Client, inputRound uint64) (uint64, error) {
	if inputRound != 0 {
		return inputRound, nil
	}

	status, err := algodClient.Status().Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed getting status from algod: %v", err)
	}

	return status.LastRound, nil
}

func getBlock(a *algod.Client, round uint64) (types.Block, error) {
	block, err := a.Block(round).Do(context.Background())
	return block, err
}

func getVrfPrivateKey(key ed25519.PrivateKey) libsodium_wrapper.VrfPrivkey {
	var vrfPrivateKey libsodium_wrapper.VrfPrivkey
	copy(vrfPrivateKey[:], key)
	return vrfPrivateKey
}
