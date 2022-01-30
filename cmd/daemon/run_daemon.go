package daemon

import (
	"os"
	"strings"

	"github.com/algorand/go-algorand-sdk/crypto"

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
