package daemon

import (
	"fmt"
	"os"
	"strings"

	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/crypto"

	log "github.com/sirupsen/logrus"

	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/spf13/cobra"
)

const (
	waitBetweenBlocksMS = 4500
)

var (
	appCreatorMnemonic      string
	approvalProgramFilename string
	clearProgramFilename    string
	signingMnemonicString   string // the mnemonic for signing vrf responses
	vrfMnemonicString       string // the mnemonic for generating the vrf
	serviceMnemonicString   string // the mnemonic for the service account (used to send responses to the smart-contract)
	startingRound           uint64 // the round from which the daemon starts scanning
	writeBlockInterval      uint64 // the number of rounds to wait before writing again

	AlgodAddress = os.Getenv("AF_ALGOD_ADDRESS")
	AlgodToken   = os.Getenv("AF_ALGOD_TOKEN")
	logLevelEnv  = strings.ToLower(os.Getenv("VRF_LOG_LEVEL"))
)

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
	RunDaemonCmd.MarkFlagRequired("signing-mnemonic")

	RunDaemonCmd.Flags().StringVar(&vrfMnemonicString, "vrf-mnemonic", "",
		"25-word mnemonic of the oracle for computing vrf (required)")
	RunDaemonCmd.MarkFlagRequired("vrf-mnemonic")

	RunDaemonCmd.Flags().StringVar(&serviceMnemonicString, "service-mnemonic", "",
		"25-word mnemonic of the service for writing the response (required)")
	RunDaemonCmd.MarkFlagRequired("service-mnemonic")

	RunDaemonCmd.Flags().StringVar(&appCreatorMnemonic, "app-creator-mnemonic", "",
		"25-word mnemonic of the app creator account used for creating the application (required)")
	RunDaemonCmd.MarkFlagRequired("app-creator-mnemonic")

	RunDaemonCmd.Flags().StringVar(&approvalProgramFilename, "approval-program", "", "TEAL script of the approval program")
	RunDaemonCmd.MarkFlagRequired("approval-program")

	RunDaemonCmd.Flags().StringVar(&clearProgramFilename, "clear-program", "", "TEAL script of the clear program")
	RunDaemonCmd.MarkFlagRequired("clear-program")

	RunDaemonCmd.Flags().Uint64Var(&startingRound, "round", 0,
		"the round to start scanning from (optional. default: current round)")

	RunDaemonCmd.Flags().Uint64Var(&startingRound, "write-interval", 8,
		"number of blocks to wait before writing again")
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

func AccountFromMnemonic(mn string) (crypto.Account, error) {
	acct := crypto.Account{}

	pk, err := mnemonic.ToPrivateKey(mn)
	if err != nil {
		return acct, err
	}

	addr, err := crypto.GenerateAddressFromSK(pk)
	if err != nil {
		return acct, err
	}

	return crypto.Account{
		PrivateKey: pk,
		Address:    addr,
	}, nil
}

var RunDaemonCmd = &cobra.Command{
	Use:   "run-daemon",
	Short: "runs the daemon",
	Run: func(cmd *cobra.Command, args []string) {
		vrfd := VRFDaemon{}

		if err := TestEnvironmentVariables(); err != nil {
			log.Fatalf("error testing environment variables: %+v", err)
		}

		algodClient, err := InitClients(AlgodAddress, AlgodToken)
		if err != nil {
			log.Fatalf("failed to initialize clients: %+v", err)
		}
		vrfd.AlgodClient = algodClient

		signerAcct, err := AccountFromMnemonic(signingMnemonicString)
		if err != nil {
			log.Fatalf("invalid signing mnemonic: %v", err)
		}
		vrfd.Signer = signerAcct

		vrfAcct, err := AccountFromMnemonic(vrfMnemonicString)
		if err != nil {
			log.Errorf("invalid vrf mnemonic: %v", err)
			return
		}
		vrfd.VRF = vrfAcct

		appAcct, err := AccountFromMnemonic(appCreatorMnemonic)
		if err != nil {
			log.Fatalf("invalid app creator mnemonic: %v", err)
		}
		vrfd.AppCreator = appAcct

		sa, err := AccountFromMnemonic(serviceMnemonicString)
		if err != nil {
			log.Fatalf("Failed to create service account from mnemonic: %v", err)
		}
		vrfd.ServiceAccount = sa

		startingRound, err = getStartingRound(algodClient, startingRound)
		if err != nil {
			log.Fatalf("failed to get starting round: %+v", err)
		}
		vrfd.CurrentRound = (startingRound / writeBlockInterval) * writeBlockInterval

		log.Infof("creating applications...")
		vrfd.CreateApplications()

		log.Info("running...")
		vrfd.Start()
	},
}
