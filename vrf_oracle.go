package main

import (
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/client/v2/indexer"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/transaction"
	"github.com/algorand/go-algorand-sdk/types"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/spf13/cobra"
)

var (
	signingMnemonicString string
	vrfMnemonicString	  string
	ownerAddressString    string
	startingRound         uint64
	oFee                  uint64
	algodAddress          = os.Getenv("AF_ALGOD_ADDRESS")
	algodToken            = os.Getenv("AF_ALGOD_TOKEN")
	indexerAddress        = os.Getenv("AF_IDX_ADDRESS")
	indexerToken          = os.Getenv("AF_IDX_TOKEN")
	logLevelEnv			  = strings.ToLower(os.Getenv("VRF_LOG_LEVEL"))
)

const (
	constNotePrefix     = "vrf-v0"
	waitBetweenBlocksMS = 4000
	minNoteLength       = 151 // len("vrf-v1") + len(opk) + len(OOwnerAddr) + len(S) + len(T) + len(x) + len(appId) + 1
	oracleEscrowLogicPrefixBase64 = "MgQiE0AAVzEWIxJAABcxFiQSQAABADEQJBIx" +
		"CCMSEDEJKBIQQzEQJRIxGCkXEhA2GgAqEhA2GgErEhA2GgMnBBIQNhwBJwUSEDEAK1A2GgJQJwRQNhoEUC0nBgQQQyND"
)

type VrfRequest struct {
	oraclePublicKey ed25519.PublicKey
	ownerAddress    types.Address
	sender          types.Address
	blockNumber     uint64
	blockNumberBytes [8]byte
	x               [32]byte
	appID           uint64
	appIDBytes 		[8]byte
	arg0            string
}

func (r *VrfRequest) OracleTealParams() (OracleTealParams, error) {
	var result OracleTealParams

	result.Arg0 = r.arg0
	result.AppIDHex = fmt.Sprintf("0x%016x", r.appID)
	result.Block = fmt.Sprintf("%08d", r.blockNumber)
	result.Sender = r.sender
	result.OwnerAddr = r.ownerAddress
	result.SigningPKb32 = base32.StdEncoding.EncodeToString(r.oraclePublicKey)
	result.Xb32 = base32.StdEncoding.EncodeToString(r.x[:])

	return result, result.Validate()
}

func markFlagRequired(flag *pflag.FlagSet, name string) {
	err := cobra.MarkFlagRequired(flag, name)
	if err != nil {
		panic(err)
	}
}

func setLogger() {
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
	setLogger()

	rootCmd.Flags().StringVar(&signingMnemonicString, "signing-mnemonic", "",
		"25-word mnemonic of the oracle for signing (required)")
	markFlagRequired(rootCmd.Flags(), "signing-mnemonic")

	rootCmd.Flags().StringVar(&vrfMnemonicString, "vrf-mnemonic", "",
		"25-word mnemonic of the oracle for computing vrf (required)")
	markFlagRequired(rootCmd.Flags(), "vrf-mnemonic")

	rootCmd.Flags().StringVar(&ownerAddressString, "owner", "", "the oracle's owner address (required)")
	markFlagRequired(rootCmd.Flags(), "owner")

	rootCmd.Flags().Uint64Var(&startingRound, "round", 0,
		"the round to start scanning from (optional. default: current round)")

	rootCmd.Flags().Uint64Var(&oFee, "oracle-fee", 1000,
		"the fee payed to the oracle for its service in MicroAlgos (optional)")

}

func computeWaitFactor(roundFromIndexer uint64, roundToFetch uint64) float64 {
	if roundFromIndexer <= roundToFetch {
		return 1
	}
	return 1 / float64(roundFromIndexer-roundToFetch)
}

func buildAnswerPhaseTransactionsGroup(vrfRequest VrfRequest, blockSeed, vrfOutput, oeSuffix []byte, signedVrfOutput types.Signature, sp types.SuggestedParams, oracleEscrow, ownerAddress types.Address, lsig types.LogicSig) ([]byte, error) {
	appArgs := [][]byte{
		[]byte(vrfRequest.arg0),
		vrfRequest.blockNumberBytes[:],
		blockSeed,
		vrfRequest.x[:],
		vrfOutput,
		signedVrfOutput[:],
		oeSuffix,
	}
	lsig.Args = [][]byte{signedVrfOutput[:]}
	accounts := []string{vrfRequest.sender.String()}
	appCall, err := future.MakeApplicationNoOpTx(
		vrfRequest.appID,
		appArgs,
		accounts,
		nil,
		nil,
		sp,
		oracleEscrow,
		nil,
		types.Digest{},
		[32]byte{},
		types.Address{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed creating app call: %v", err)
	}
	paymentTransactions, err := future.MakePaymentTxn(
		oracleEscrow.String(),
		oracleEscrow.String(),
		0,
		nil,
		ownerAddress.String(),
		sp,
	)
	if err != nil {
		return nil, fmt.Errorf("failed creating payment transaction: %v", err)
	}
	grouped, err := transaction.AssignGroupID([]types.Transaction{appCall, paymentTransactions}, "")
	if err != nil {
		return nil, fmt.Errorf("failed grouping transactions: %v", err)
	}
	_, signedAppCall, err := crypto.SignLogicsigTransaction(lsig, grouped[0])
	if err != nil {
		return nil, fmt.Errorf("failed signing app call: %v", err)
	}
	_, signedPayment, err := crypto.SignLogicsigTransaction(lsig, grouped[1])
	if err != nil {
		return nil, fmt.Errorf("failed signing payment transaction: %v", err)
	}
	signedGroup := append(signedAppCall, signedPayment...)
	return signedGroup, nil
}

func getVrfPrivateKey(key ed25519.PrivateKey) VrfPrivkey {
	var vrfPrivateKey VrfPrivkey
	copy(vrfPrivateKey[:], key)
	return vrfPrivateKey
}

func buildVrfInput(blockNumber [8]byte, blockSeed []byte, x [32]byte) [sha512.Size256]byte {
	toHash := append(blockNumber[:], blockSeed...)
	toHash = append(toHash, x[:]...)
	return sha512.Sum512_256(toHash)
}

func computeAndSignVrf(blockNumber [8]byte, blockSeed []byte, x [32]byte, oracleEscrowAddress types.Address, oracleSigningKey ed25519.PrivateKey, oracleVrfKey ed25519.PrivateKey) (types.Signature, []byte, error) {
	vrfInput := buildVrfInput(blockNumber, blockSeed, x)
	vrfPrivateKey := getVrfPrivateKey(oracleVrfKey)
	proof, ok := vrfPrivateKey.proveBytes(vrfInput[:])
	if !ok {
		return types.Signature{}, []byte{}, fmt.Errorf("error computing vrf proof")
	}
	vrfOutput, ok := proof.Hash()
	if !ok {
		return types.Signature{}, []byte{}, fmt.Errorf("error computing vrf output")
	}
	toSign := append(oracleEscrowAddress[:], blockNumber[:]...)
	toSign = append(toSign, blockSeed...)
	toSign = append(toSign, x[:]...)
	toSign = append(toSign, vrfOutput[:]...)
	sig, err := crypto.TealSign(oracleSigningKey, toSign, oracleEscrowAddress)
	if err != nil {
		return types.Signature{}, []byte{}, fmt.Errorf("error signing vrf output")
	}
	return sig, vrfOutput[:], nil
}

func getOracleLogic(vrfRequest VrfRequest) (types.LogicSig, error) {
	oracleTealParams, err := vrfRequest.OracleTealParams()
	if err != nil {
		return types.LogicSig{}, fmt.Errorf("bad TEAL template params: %v", err)
	}
	return types.LogicSig{
		Logic: CompileOracle(oracleTealParams),
	}, nil
}

func handleRequestsForCurrentRound(requestsToHandle []VrfRequest, block models.Block, signingPrivateKey,
	vrfPrivateKey ed25519.PrivateKey, ownerAddress types.Address, oeSuffix []byte,
	suggestedParams types.SuggestedParams, algodClient *algod.Client) {
	for _, currentRequestHandled := range requestsToHandle {
		oracleLogicSig, err := getOracleLogic(currentRequestHandled)
		if err != nil {
			log.Warnf("failed computing LogicSig for %v: %v. skipping...", currentRequestHandled, err)
			continue
		}
		log.Debugf("lsig b64: %v", base64.StdEncoding.EncodeToString(oracleLogicSig.Logic))
		oracleEscrowAddr := crypto.AddressFromProgram(oracleLogicSig.Logic)
		sig, vrfOutput, err := computeAndSignVrf(
			currentRequestHandled.blockNumberBytes,
			block.Seed,
			currentRequestHandled.x,
			oracleEscrowAddr,
			signingPrivateKey,
			vrfPrivateKey,
		)
		if err != nil {
			log.Warnf("failed computing vrf for %v: %v. skipping...", currentRequestHandled, err)
			continue
		}
		stxBytes, err := buildAnswerPhaseTransactionsGroup(
			currentRequestHandled,
			block.Seed,
			vrfOutput,
			oeSuffix,
			sig,
			suggestedParams,
			oracleEscrowAddr,
			ownerAddress,
			oracleLogicSig,
		)
		if err != nil {
			log.Warnf(
				"failed building transactions group for %v: %v. skipping...",
				currentRequestHandled,
				err,
			)
			continue
		}
		log.Debugf("stxbytes bas64: %v", base64.StdEncoding.EncodeToString(stxBytes))
		txId, err := algodClient.SendRawTransaction(stxBytes).Do(context.Background())
		if err != nil {
			log.Warnf(
				"failed sending transactions group for %v: %v. skipping...",
				currentRequestHandled,
				err,
			)
			continue
		}
		log.Infof("Sent transaction %s", txId)
	}
}

func getSuggestedParams(algodClient *algod.Client) (types.SuggestedParams, error) {
	var sp types.SuggestedParams
	err := Retry(1, 5,
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

func getBlock(indexerClient *indexer.Client, round uint64) (models.Block, error) {
	var block models.Block
	err := Retry(1, 5,
		func() error {
			var err error
			block, err = indexerClient.LookupBlock(round).Do(context.Background())
			return err
		},
		func(err error) {
			log.Warnf("can't retrieve block %d, trying again...: %v", round, err)
		},
	)
	return block, err
}

func getVrfRequestsToHandle(h *VrfRequestsHeap, currentRound uint64) []VrfRequest {
	var result []VrfRequest
	for{
		if len(*h) < 1 {
			break
		}
		top := (*h)[0]
		if top.blockNumber > currentRound {
			log.Infof("handled all requests for round %d", currentRound)
			break
		}
		currentNoteHandled := heap.Pop(h).(VrfRequest)
		if currentNoteHandled.blockNumber < currentRound {
			log.Warnf("found unhandled old request in queue: %v", currentNoteHandled)
			continue
		}
		result = append(result, currentNoteHandled)
	}
	return result
}

func parseNote(note []byte) (VrfRequest, error) {
	var result VrfRequest
	var err error

	if len(note) < minNoteLength || string(note[:6]) != constNotePrefix{
		return result, fmt.Errorf("error parsing note length")
	}

	result.oraclePublicKey = make([]byte, ed25519.PublicKeySize)
	copy(result.oraclePublicKey[:], note[6:38])
	copy(result.ownerAddress[:], note[38:70])
	copy(result.sender[:], note[70:102])
	result.blockNumber, err = strconv.ParseUint(string(note[102:110]), 10, 64)
	if err != nil {
		return result, fmt.Errorf("error parsing note block number %v", note[102:110])
	}
	copy(result.blockNumberBytes[:], note[102:110])
	copy(result.x[:], note[110:142])
	result.appID, err = strconv.ParseUint(string(note[142:150]), 10, 64)
	if err != nil {
		return result, fmt.Errorf("error parsing note appID %v", note[142:150])
	}
	copy(result.appIDBytes[:], note[142:150])
	result.arg0 = string(note[150:])

	return result, nil
}

func validateTransaction(transaction models.Transaction, currentRound uint64) (VrfRequest, error) {
	// TODO validate receiver is ORACLE ESCROW
	parsedNote, err := parseNote(transaction.Note)
	if err != nil {
		return parsedNote, err
	}
	if currentRound >= parsedNote.blockNumber {
		return parsedNote, fmt.Errorf("block number is not in the future")
	}
	if transaction.Sender != parsedNote.sender.String() {
		return parsedNote, fmt.Errorf("transaction sender doesn't match the note")
	}
	return parsedNote, nil
}

func storeRequestsInHeap(h *VrfRequestsHeap, transactions []models.Transaction, currentRound uint64) {
	for _, txn := range transactions {
		parsedNote, err := validateTransaction(txn, currentRound)
		if err != nil {
			log.Warnf("%v", err)
			continue
		}
		log.Debugf("Found transaction!")
		heap.Push(h, parsedNote)
	}
}

func getTransactionsFromIndexer(indexerClient *indexer.Client, round uint64, notePrefix []byte, oFee uint64) (models.TransactionsResponse, error) {
	var transactionsResponse models.TransactionsResponse
	err := Retry(1, 5,
		func() error {
			var err error
			transactionsResponse, err = indexerClient.SearchForTransactions().
				Round(round).
				NotePrefix(notePrefix).
				CurrencyGreaterThan(oFee).
				Do(context.Background())
			if err == nil && transactionsResponse.CurrentRound < round {
				return fmt.Errorf("%d not available yet, got %d", round, transactionsResponse.CurrentRound)
			}
			return err
		},
		func(err error) {
			log.Warnf("can't retrieve block %d, trying again...: %v", round, err)
		},
	)
	return transactionsResponse, err
}

func getOracleEscrowLogicSuffix() ([]byte, error) {
	oeSuffix, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(oracleEscrowLogicPrefixBase64)
	if err != nil {
		return []byte{}, err
	}
	oeSuffixHash := sha512.Sum512_256(oeSuffix)
	log.Debugf(
		"oe suffix: %s oe suffix hash %s",
		base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(oeSuffix),
		base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(oeSuffixHash[:]),
	)
	return oeSuffix, nil
}

func mainLoop(startingRound uint64, algodClient *algod.Client, indexerClient *indexer.Client, notePrefix []byte,
	signingPrivateKey, vrfPrivateKey ed25519.PrivateKey, ownerAddress types.Address) {
	oeSuffix, err := getOracleEscrowLogicSuffix()
	if err != nil {
		log.Errorf("invalid oracle escrow suffix: %v", err)
		return
	}
	waitFactor := float64(1)
	currentRound := startingRound
	h := &VrfRequestsHeap{}
	heap.Init(h)
	for {
		sleepTime := time.Duration(waitFactor*waitBetweenBlocksMS) * time.Millisecond
		log.Debugf("sleeping %v", sleepTime)
		time.Sleep(sleepTime)
		log.Infof("fetching transactions from block: %d", currentRound)
		transactionsResponse, err := getTransactionsFromIndexer(indexerClient, currentRound, notePrefix, oFee)
		if err != nil {
			log.Errorf("error getting transaction of block %d from indexer: %v", currentRound, err)
			return
		}
		log.Debugf("latest block from indexer: %d", transactionsResponse.CurrentRound)

		storeRequestsInHeap(h, transactionsResponse.Transactions, currentRound)

		requestsToHandle := getVrfRequestsToHandle(h, currentRound)
		if len(requestsToHandle) != 0 {
			log.Infof("getting block seed for %d", currentRound)
			block, err := getBlock(indexerClient, currentRound)
			if err != nil {
				log.Errorf("error getting block seed of block %d from indexer", currentRound)
				return
			}

			suggestedParams, err := getSuggestedParams(algodClient)
			if err != nil {
				log.Errorf("error getting suggested params from algod: %v", err)
				return
			}
			handleRequestsForCurrentRound(
				requestsToHandle,
				block,
				signingPrivateKey,
				vrfPrivateKey,
				ownerAddress,
				oeSuffix,
				suggestedParams,
				algodClient,
			)
		}

		waitFactor = computeWaitFactor(transactionsResponse.CurrentRound, currentRound)
		currentRound++
	}
}

func buildNotePrefix(constNotePrefix string, opk ed25519.PublicKey, ownerAddress types.Address) []byte {
	//ownerAddressStringNoChecksum := addressToStringNoChecksum(ownerAddress)
	prefix := append([]byte(constNotePrefix), opk...)
	prefix = append(prefix, ownerAddress[:]...)
	return prefix
}

func pubKeyFromEd25519PrivateKey(sk ed25519.PrivateKey) ed25519.PublicKey {
	pk := make([]byte, ed25519.PublicKeySize)
	copy(pk[:], sk[32:])
	return pk
}

func getStartingRound(inputRound uint64, algodClient *algod.Client) (uint64, error) {
	if inputRound != 0 {
		return inputRound, nil
	}
	status, err := algodClient.Status().Do(context.Background())
	if err != nil {
		return inputRound, fmt.Errorf("failed getting status from algod: %v", err)
	}
	return status.LastRound, nil
}

func initClients(algodAddress, algodToken, indexerAddress, indexerToken string) (*algod.Client, *indexer.Client, error) {
	var failedClients []string
	algodClient, err := algod.MakeClient(algodAddress, algodToken)
	if err != nil {
		failedClients = append(failedClients, "algod")
		log.Error(err)
	}
	indexerClient, err := indexer.MakeClient(indexerAddress, indexerToken)
	if err != nil {
		failedClients = append(failedClients, "indexer")
		log.Error(err)
	}
	if len(failedClients) > 0 {
		err = fmt.Errorf("failed creating the following client(s): %s", strings.Join(failedClients, ","))
	}
	return algodClient, indexerClient, err
}

func testEnvironmentVariables() error {
	var missing []string
	if algodAddress == "" {
		missing = append(missing, "AF_ALGOD_ADDRESS")
	}
	if indexerAddress == "" {
		missing = append(missing, "AF_IDX_ADDRESS")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s environment variable(s)", strings.Join(missing, ","))
	}
	return nil
}

var rootCmd = &cobra.Command{
	Use:   "vrf-oracle",
	Short: "service that reads VRF requests from the blockchain, and broadcasts back the response",
	Run: func(cmd *cobra.Command, args []string) {
		err := testEnvironmentVariables()
		if err != nil {
			log.Error(err)
			return
		}
		algodClient, indexerClient, err := initClients(algodAddress, algodToken, indexerAddress, indexerToken)
		if err != nil {
			log.Error(err)
			return
		}
		startingRound, err = getStartingRound(startingRound, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		signingPrivateKey, err := mnemonic.ToPrivateKey(signingMnemonicString)
		if err != nil {
			log.Errorf("invalid signing mnemonic: %v", err)
			return
		}
		vrfPrivateKey, err := mnemonic.ToPrivateKey(vrfMnemonicString)
		if err != nil {
			log.Errorf("invalid vrf mnemonic: %v", err)
			return
		}
		ownerAddress, err := types.DecodeAddress(ownerAddressString)
		if err != nil {
			log.Errorf("invalid owner address: %v", err)
			return
		}
		log.Info("running...")
		opk := pubKeyFromEd25519PrivateKey(signingPrivateKey)
		notePrefix := buildNotePrefix(constNotePrefix, opk, ownerAddress)
		log.Debug(base64.StdEncoding.EncodeToString(notePrefix))

		mainLoop(
			startingRound,
			algodClient,
			indexerClient,
			notePrefix,
			signingPrivateKey,
			vrfPrivateKey,
			ownerAddress,
		)
		//cmd.HelpFunc()(cmd, args)
	},
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}
}
