package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
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
	numOfDummyTxns      = 4                        // Number of extra `dummy` txns to help pad opcode budget
	dummyAppBytes       = []byte{0x05, 0x81, 0x01} // pragma 5; pushint 1;
	waitBetweenBlocksMS = 4500                     // Num ms between blocks
)

type VRFDaemon struct {
	AlgodClient *algod.Client // Client used to interact with the chain

	ApprovalBytes []byte
	ClearBytes    []byte

	DummyAppID  uint64        // Dummy app used to increase budget
	AppID       uint64        // Application that validates and stores randomness
	AppHashAddr types.Address // Hash of application approval program, needed to produce ed25519 bytes to verify

	WriteInterval uint64 // Number of rounds between writing updated value
	CurrentRound  uint64 // The latest round we've sesen

	Signer         crypto.Account // Signs VRF output
	VRF            crypto.Account // Generates VRF output
	AppCreator     crypto.Account // Creates application
	ServiceAccount crypto.Account // Sends updates
}

func NewFromConfig(path string) *VRFDaemon {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read file %s:  %+v", path, err)
	}

	conf := &Config{}
	if err := json.Unmarshal(b, conf); err != nil {
		log.Fatalf("Failed to unmarshal json: %+v", err)
	}

	client, err := algod.MakeClient(fmt.Sprintf("%s:%d", conf.AlgodHost, conf.AlgodPort), conf.AlgodToken)
	if err != nil {
		log.Fatalf("Failed to make client: %+v", err)
	}

	// Setup accounts
	signer, err := AccountFromString(conf.Signer)
	if err != nil {
		log.Fatalf("Failed to parse signer: %+v", err)
	}

	vrf, err := AccountFromString(conf.VRF)
	if err != nil {
		log.Fatalf("Failed to parse vrf: %+v", err)
	}

	creator, err := AccountFromString(conf.Creator)
	if err != nil {
		log.Fatalf("Failed to parse creator: %+v", err)
	}

	service, err := AccountFromString(conf.Service)
	if err != nil {
		log.Fatalf("Failed to parse service: %+v", err)
	}

	approval, err := base64.StdEncoding.DecodeString(conf.ApprovalSource)
	if err != nil {
		log.Fatalf("Failed to decode approval program: %+v", err)
	}

	clear, err := base64.StdEncoding.DecodeString(conf.ClearSource)
	if err != nil {
		log.Fatalf("Failed to decode clear program: %+v", err)
	}

	return &VRFDaemon{
		AlgodClient: client,

		ApprovalBytes: approval,
		ClearBytes:    clear,

		DummyAppID:  uint64(conf.DummyAppID),
		AppID:       uint64(conf.AppID),
		AppHashAddr: crypto.AddressFromProgram(approval),

		WriteInterval: uint64(conf.WriteInterval),
		CurrentRound:  uint64(conf.Start),

		Signer:         signer,
		VRF:            vrf,
		AppCreator:     creator,
		ServiceAccount: service,
	}
}

// New returns a pointer to a VRFDaemon, you should call `CreateApplications` (if necessary) and `Start` to kick it off
func New(client *algod.Client, signer, vrf, app, service crypto.Account, writeInterval, roundStart uint64, approval, clear []byte) *VRFDaemon {
	return &VRFDaemon{
		AlgodClient: client,

		ApprovalBytes: approval,
		ClearBytes:    clear,
		AppHashAddr:   crypto.AddressFromProgram(approval),

		Signer:         signer,
		VRF:            vrf,
		AppCreator:     app,
		ServiceAccount: service,

		WriteInterval: writeInterval,
		CurrentRound:  roundStart,
	}
}

// CreateApplications creates the dummy app used for budget increase
// and the main oracle application
func (v *VRFDaemon) CreateApplications() error {

	if v.DummyAppID != 0 {
		return fmt.Errorf("already have dummy app id: %d", v.DummyAppID)
	}

	if v.AppID != 0 {
		return fmt.Errorf("already have oracle app id: %d", v.AppID)
	}

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

// Start starts the loop that is continuously checking for new rounds.
// If it finds a new round and the round is one we should write for
// it creates a new vrf and sends a transaction to update the state of the application
func (v *VRFDaemon) Start() {
	for {
		sleepTime := time.Duration(waitBetweenBlocksMS) * time.Millisecond
		log.Debugf("sleeping %v", sleepTime)

		time.Sleep(sleepTime)

		log.Infof("getting block seed for %d", v.CurrentRound+1)
		block, err := getBlock(v.AlgodClient, v.CurrentRound+1)
		if err != nil {
			log.Errorf("error getting block %d from algod: %+v", v.CurrentRound, err)
			continue
		}

		if block.Round < types.Round(v.CurrentRound) {
			// We already saw this
			continue
		}

		if uint64(block.Round)%v.WriteInterval != 0 {
			// We only want to write on the interval specified
			// but we should update regardless to make sure we request the next block
			v.CurrentRound = uint64(block.Round)
			continue
		}

		if err := v.HandleBlock(block); err != nil {
			log.Warnf("Failed to handle request: %+v", err)
			continue
		}

		// Update our last seen round only after we've actually handled it
		v.CurrentRound = uint64(block.Round)
	}
}

// handles requests for the current round: computes the VRF output and sends it to the smart-contract
func (v *VRFDaemon) HandleBlock(block types.Block) error {

	blockNumberBytes := roundAsBytes(uint64(block.Round))
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

	blockNumberBytes := roundAsBytes(uint64(block.Round))
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
	sig, err := crypto.TealSign(v.Signer.PrivateKey, toSign, v.AppHashAddr)
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

	block, err := getBlock(v.AlgodClient, v.CurrentRound)
	if err != nil {
		return 0, fmt.Errorf("failed to get block %d from algod: %+v", v.CurrentRound, err)
	}

	signedVrfOutput, vrfOutput, err := v.ComputeAndSignVRFForRound(block)
	if err != nil {
		return 0, fmt.Errorf("failed to compute vrf for %d: %v", v.CurrentRound, err)
	}

	globalStateSchema := types.StateSchema{NumUint: 0, NumByteSlice: 64}
	localStateSchema := types.StateSchema{NumUint: 0, NumByteSlice: 0}

	blockNumberBytes := roundAsBytes(v.CurrentRound)
	binary.BigEndian.PutUint64(blockNumberBytes, v.CurrentRound)
	args := [][]byte{
		blockNumberBytes, v.Signer.PrivateKey[32:], v.VRF.PrivateKey[32:],
		block.BlockHeader.Seed[:], vrfOutput, signedVrfOutput[:],
	}

	appCall, err := future.MakeApplicationCreateTx(
		false, v.ApprovalBytes, v.ClearBytes, globalStateSchema, localStateSchema, args,
		nil, nil, nil, sp, v.AppCreator.Address, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to make app create txn: %+v", err)
	}

	appCalls := []types.Transaction{appCall}
	for i := 0; i < numOfDummyTxns; i++ {
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

func getBlock(a *algod.Client, round uint64) (block types.Block, err error) {
	block, err = a.Block(round).Do(context.Background())
	return
}

func getVrfPrivateKey(key ed25519.PrivateKey) libsodium_wrapper.VrfPrivkey {
	var vrfPrivateKey libsodium_wrapper.VrfPrivkey
	copy(vrfPrivateKey[:], key)
	return vrfPrivateKey
}

func roundAsBytes(round uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, round)
	return b
}
