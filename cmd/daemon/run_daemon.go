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

	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	libsodium_wrapper "github.com/ori-shem-tov/vrf-oracle/libsodium-wrapper"

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

	AlgodAddress = os.Getenv("AF_ALGOD_ADDRESS")
	AlgodToken   = os.Getenv("AF_ALGOD_TOKEN")
	logLevelEnv  = strings.ToLower(os.Getenv("VRF_LOG_LEVEL"))
)

const (
	waitBetweenBlocksMS = 4500
	writeBlockInterval  = 8
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

	RunDaemonCmd.Flags().StringVar(&appCreatorMnemonic, "app-creator-mnemonic", "", "25-word mnemonic of the app creator")
	MarkFlagRequired(RunDaemonCmd.Flags(), "app-creator-mnemonic")

	RunDaemonCmd.Flags().StringVar(&approvalProgramFilename, "approval-program", "", "TEAL script of the approval program")
	MarkFlagRequired(RunDaemonCmd.Flags(), "approval-program")

	RunDaemonCmd.Flags().StringVar(&clearProgramFilename, "clear-program", "", "TEAL script of the clear program")
	MarkFlagRequired(RunDaemonCmd.Flags(), "clear-program")
}

type VRFDaemon struct {
	AlgodClient *algod.Client // Client used to interact with the chain

	DummyAppID  uint64        // Dummy app used to increase budget
	AppID       uint64        // Application that validates and stores randomness
	AppHashAddr types.Address // Hash of application approval program, needed to produce ed25519 bytes to verify

	CurrentRound uint64 // The latest round we've sesen

	SigningPrivateKey    ed25519.PrivateKey
	VRFPrivateKey        ed25519.PrivateKey
	AppCreatorPrivateKey ed25519.PrivateKey

	ServiceAccount crypto.Account
}

func (v *VRFDaemon) CreateApplication() error {
	suggestedParams, err := v.AlgodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("Failed to get suggested params from algod: %v", err)
	}

	log.Info("creating dummy app...")
	dummyAppID, err := createDummyApp(
		[]byte{0x05, 0x20, 0x01, 0x01, 0x22}, v.AppCreatorPrivateKey, v.AlgodClient, suggestedParams,
	)
	if err != nil {
		log.Fatalf("Failed to create dummy app: %+v", err)
	}
	v.DummyAppID = dummyAppID

	log.Info("Compiling teal")
	approvalBytes, clearBytes, err := compileTeal(approvalProgramFilename, clearProgramFilename, v.AlgodClient)
	if err != nil {
		log.Fatalf("Failed to compile teal: %+v", err)
	}
	v.AppHashAddr = crypto.AddressFromProgram(approvalBytes)
	log.Infof("Approval hash: %s", v.AppHashAddr)

	block, err := getBlock(v.AlgodClient, v.CurrentRound)
	if err != nil {
		log.Fatalf("Failed to get block seed of block %d from algod", v.CurrentRound)
	}

	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, startingRound)
	signedVrfOutput, vrfOutput, err := computeAndSignVrf(
		blockNumberBytes, block.BlockHeader.Seed[:], v.AppHashAddr, v.SigningPrivateKey, v.VRFPrivateKey,
	)

	if err != nil {
		log.Fatalf("Failed to compute vrf for %d: %v", v.CurrentRound, err)
	}

	globalStateSchema := types.StateSchema{NumUint: 0, NumByteSlice: 64}
	localStateSchema := types.StateSchema{NumUint: 0, NumByteSlice: 0}

	appArgs := [][]byte{
		blockNumberBytes, v.SigningPrivateKey[32:], v.VRFPrivateKey[32:],
		block.BlockHeader.Seed[:], vrfOutput, signedVrfOutput[:],
	}

	stxBytes, err := generateSignedAppCreate(
		approvalBytes, clearBytes, globalStateSchema, localStateSchema,
		v.AppCreatorPrivateKey, appArgs, suggestedParams, dummyAppID,
	)
	if err != nil {
		log.Fatalf("Failed to make app create transaction")
	}

	txID, err := v.AlgodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		log.Fatalf("Failed sending app create transaction: %v", err)
	}

	res, err := future.WaitForConfirmation(v.AlgodClient, txID, 2, context.Background())
	if err != nil {
		log.Fatalf("Failed while waiting for app create to be confirmed: %+v", err)
	}

	v.AppID = res.ApplicationIndex

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

		if block.Round%writeBlockInterval != 0 {
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

	signedVrfOutput, vrfOutput, err := computeAndSignVrf(
		blockNumberBytes, blockSeed, v.AppHashAddr, v.SigningPrivateKey, v.VRFPrivateKey,
	)
	if err != nil {
		return fmt.Errorf("failed to compute and sign vrf: %+v", err)
	}

	sp, err := v.AlgodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %+v", err)
	}

	stxBytes, err := buildAnswerPhaseTransactionsGroup(
		v.AppID, v.DummyAppID, v.ServiceAccount, blockNumberBytes, blockSeed, vrfOutput, signedVrfOutput, sp,
	)
	if err != nil {
		return fmt.Errorf("failed building transactions group for %d: %v", block.Round, err)
	}

	txid, err := v.AlgodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed sending transactions group for %v: %v", block.Round, err)
	}

	log.Infof("Sent request txn: %s", txid)

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

		vrfd := VRFDaemon{}

		algodClient, err := InitClients(AlgodAddress, AlgodToken)
		if err != nil {
			log.Errorf("failed to initialize clients: %+v", err)
			return
		}
		vrfd.AlgodClient = algodClient

		startingRound, err = getStartingRound(startingRound, algodClient)
		if err != nil {
			log.Errorf("failed to get starting round: %+v", err)
			return
		}
		vrfd.CurrentRound = (startingRound / writeBlockInterval) * writeBlockInterval

		signingPrivateKey, err := mnemonic.ToPrivateKey(signingMnemonicString)
		if err != nil {
			log.Errorf("invalid signing mnemonic: %v", err)
			return
		}

		vrfd.SigningPrivateKey = signingPrivateKey

		vrfPrivateKey, err := mnemonic.ToPrivateKey(vrfMnemonicString)
		if err != nil {
			log.Errorf("invalid vrf mnemonic: %v", err)
			return
		}
		vrfd.VRFPrivateKey = vrfPrivateKey

		appCreatorPrivateKey, err := mnemonic.ToPrivateKey(appCreatorMnemonic)
		if err != nil {
			log.Errorf("invalid app creator mnemonic: %v", err)
			return
		}
		vrfd.AppCreatorPrivateKey = appCreatorPrivateKey

		servicePrivateKey, err := mnemonic.ToPrivateKey(serviceMnemonicString)
		if err != nil {
			log.Errorf("invalid service mnemonic: %v", err)
			return
		}

		serviceAddress, err := crypto.GenerateAddressFromSK(servicePrivateKey)
		if err != nil {
			log.Errorf("invalid service key: %+v", err)
			return
		}

		vrfd.ServiceAccount = crypto.Account{
			PrivateKey: servicePrivateKey,
			Address:    serviceAddress,
		}

		vrfd.CreateApplication()

		startingRound += writeBlockInterval

		log.Info("running...")

		vrfd.Start()
	},
}

// generates a group of 3 application calls:
// the 1st App call is to the smart-contract to respond the VRF output, while the 2nd and 3rd are dummy app calls used
// to increase the cost pool.
func buildAnswerPhaseTransactionsGroup(appID, dummyAppID uint64, serviceAccount crypto.Account, blockNumber,
	blockSeed, vrfOutput []byte, signedVrfOutput types.Signature, sp types.SuggestedParams) ([]byte, error) {

	appArgs := [][]byte{
		[]byte("respond"), blockNumber, blockSeed, vrfOutput, signedVrfOutput[:],
	}

	appCall, err := future.MakeApplicationNoOpTx(
		appID, appArgs, nil, nil, nil, sp, serviceAccount.Address, nil, types.Digest{}, [32]byte{}, types.Address{},
	)

	if err != nil {
		return nil, fmt.Errorf("failed creating app call: %v", err)
	}
	numOfDummyTxns := 4
	appCall.Fee *= types.MicroAlgos(1 + numOfDummyTxns)

	appCalls := []types.Transaction{appCall}
	for i := 0; i < numOfDummyTxns; i++ {
		dummyAppCall, err := future.MakeApplicationNoOpTx(
			dummyAppID, nil, nil, nil, nil, sp, serviceAccount.Address,
			[]byte{byte(i)}, types.Digest{}, [32]byte{}, types.ZeroAddress,
		)

		if err != nil {
			return nil, fmt.Errorf("failed creating dummy app call: %v", err)
		}

		dummyAppCall.Fee = 0

		appCalls = append(appCalls, dummyAppCall)
	}

	grouped, err := transaction.AssignGroupID(appCalls, "")
	if err != nil {
		return nil, fmt.Errorf("failed grouping transactions: %v", err)
	}

	var signedGroup []byte
	for _, txn := range grouped {
		_, signed, err := crypto.SignTransaction(serviceAccount.PrivateKey, txn)
		if err != nil {
			return nil, fmt.Errorf("failed signing app call: %v", err)
		}
		signedGroup = append(signedGroup, signed...)
	}

	return signedGroup, nil
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
func computeAndSignVrf(blockNumber, blockSeed []byte, appApprovalHashAddress types.Address, oracleSigningKey,
	oracleVrfKey ed25519.PrivateKey) (types.Signature, []byte, error) {
	vrfInput := buildVrfInput(blockNumber, blockSeed)
	vrfPrivateKey := getVrfPrivateKey(oracleVrfKey)
	proof, ok := vrfPrivateKey.ProveBytes(vrfInput[:])
	if !ok {
		return types.Signature{}, []byte{}, fmt.Errorf("error computing vrf proof")
	}
	vrfOutput, ok := proof.Hash()
	if !ok {
		return types.Signature{}, []byte{}, fmt.Errorf("error computing vrf output")
	}
	toSign := append(blockNumber, blockSeed...)
	toSign = append(toSign, vrfOutput[:]...)
	sig, err := crypto.TealSign(oracleSigningKey, toSign, appApprovalHashAddress)
	if err != nil {
		return types.Signature{}, []byte{}, fmt.Errorf("error signing vrf output")
	}
	return sig, vrfOutput[:], nil
}

func getBlock(a *algod.Client, round uint64) (types.Block, error) {
	block, err := a.Block(round).Do(context.Background())
	return block, err
}

func generateSignedAppCreate(approvalBytes, clearBytes []byte, globalState, localState types.StateSchema,
	appCreatorSK ed25519.PrivateKey, args [][]byte, sp types.SuggestedParams, dummyAppID uint64) ([]byte, error) {

	sender, err := crypto.GenerateAddressFromSK(appCreatorSK)
	if err != nil {
		return nil, err
	}

	appCall, err := future.MakeApplicationCreateTx(
		false, approvalBytes, clearBytes, globalState, localState, args,
		nil, nil, nil, sp, sender, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
	)

	if err != nil {
		return nil, err
	}

	appCalls := []types.Transaction{appCall}
	for i := 0; i < 4; i++ {
		dummyAppCall, err := future.MakeApplicationNoOpTx(
			dummyAppID, nil, nil, nil, nil, sp, sender,
			[]byte{byte(i)}, types.Digest{}, [32]byte{}, types.ZeroAddress,
		)
		if err != nil {
			return nil, fmt.Errorf("failed creating dummy app call: %v", err)
		}
		appCalls = append(appCalls, dummyAppCall)
	}

	grouped, err := transaction.AssignGroupID(appCalls, "")
	if err != nil {
		return nil, fmt.Errorf("failed grouping transactions: %v", err)
	}

	var signedGroup []byte
	for _, txn := range grouped {
		_, signed, err := crypto.SignTransaction(appCreatorSK, txn)
		if err != nil {
			return nil, fmt.Errorf("failed signing app call: %v", err)
		}
		signedGroup = append(signedGroup, signed...)
	}

	return signedGroup, nil
}

func generateSignedDummyAppCreate(approvalBytes, clearBytes []byte, globalState, localState types.StateSchema,
	appCreatorSK ed25519.PrivateKey, args [][]byte, sp types.SuggestedParams) ([]byte, error) {
	sender, err := crypto.GenerateAddressFromSK(appCreatorSK)
	if err != nil {
		return nil, err
	}
	tx, err := future.MakeApplicationCreateTx(
		false, approvalBytes, clearBytes, globalState, localState, args,
		nil, nil, nil, sp, sender, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
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

func createDummyApp(approvalProgram []byte, appCreatorSK ed25519.PrivateKey, algodClient *algod.Client,
	suggestedParams types.SuggestedParams) (uint64, error) {

	stxBytes, err := generateSignedDummyAppCreate(
		approvalProgram, approvalProgram, types.StateSchema{}, types.StateSchema{}, appCreatorSK, nil, suggestedParams,
	)
	if err != nil {
		return 0, err
	}

	txID, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed sending app call: %v", err)
	}

	res, err := future.WaitForConfirmation(algodClient, txID, 2, context.Background())
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

func GetFromState(key []byte, state []models.TealKeyValue) (models.TealValue, bool) {
	kB64 := base64.StdEncoding.EncodeToString(key)
	for _, kv := range state {
		if kv.Key == kB64 {
			return kv.Value, true
		}
	}
	return models.TealValue{}, false
}

func InitClients(algodAddress, algodToken string) (*algod.Client, error) {
	algodClient, err := algod.MakeClient(algodAddress, algodToken)
	return algodClient, err
}

func TestEnvironmentVariables() error {
	var missing []string
	if AlgodAddress == "" {
		return fmt.Errorf("missing %s environment variable(s)", strings.Join(missing, ","))
	}
	return nil
}
