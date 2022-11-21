package main

import (
	"encoding/base64"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	"github.com/ori-shem-tov/vrf-oracle/tools"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

var (
	appCreatorMnemonic       string
	approvalProgramFilename  string
	clearProgramFilename     string
	dummyAppApprovalFilename string
	dummyAppClearFilename    string
	vrfProofString           string // base64 encoding of the VRF proof
	vrfPKAddrString          string
	startingRound            uint64 // the round from which the daemon starts scanning
	AlgodAddress             = os.Getenv("AF_ALGOD_ADDRESS")
	AlgodToken               = os.Getenv("AF_ALGOD_TOKEN")
	logLevelEnv              = strings.ToLower(os.Getenv("VRF_LOG_LEVEL"))
)

func init() {
	tools.SetLogger(logLevelEnv)

	DeployAppCmd.Flags().StringVar(&vrfProofString, "vrf-proof", "",
		"base64 encoding of the VRF proof (required)")
	tools.MarkFlagRequired(DeployAppCmd.Flags(), "vrf-proof")

	DeployAppCmd.Flags().StringVar(&vrfPKAddrString, "vrf-pk-addr", "",
		"the VRF public key as an Algorand address (required)")
	tools.MarkFlagRequired(DeployAppCmd.Flags(), "vrf-pk-addr")

	DeployAppCmd.Flags().Uint64Var(&startingRound, "starting-round", 0,
		"the round to start scanning from (optional. default: current round)")

	DeployAppCmd.Flags().StringVar(&appCreatorMnemonic, "app-creator-mnemonic", "", "25-word mnemonic of the app creator (required)")
	tools.MarkFlagRequired(DeployAppCmd.Flags(), "app-creator-mnemonic")

	DeployAppCmd.Flags().StringVar(&approvalProgramFilename, "approval-program", "", "TEAL script of the approval program (required)")
	tools.MarkFlagRequired(DeployAppCmd.Flags(), "approval-program")

	DeployAppCmd.Flags().StringVar(&clearProgramFilename, "clear-program", "", "TEAL script of the clear program (required)")
	tools.MarkFlagRequired(DeployAppCmd.Flags(), "clear-program")

	DeployAppCmd.Flags().StringVar(&dummyAppApprovalFilename, "dummy-app-approval", "", "TEAL script of the dummy app approval (required)")
	tools.MarkFlagRequired(DeployAppCmd.Flags(), "dummy-app-approval")

	DeployAppCmd.Flags().StringVar(&dummyAppClearFilename, "dummy-app-clear", "", "TEAL script of the dummy app clear (required)")
	tools.MarkFlagRequired(DeployAppCmd.Flags(), "dummy-app-clear")

}

var DeployAppCmd = &cobra.Command{
	Use:   "deploy-app",
	Short: "deploys the beacon's smart contract",
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
		startingRound, err = daemon.GetStartingRound(startingRound, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		appCreatorPrivateKey, err := mnemonic.ToPrivateKey(appCreatorMnemonic)
		if err != nil {
			log.Errorf("invalid app creator mnemonic: %v", err)
			return
		}

		appCreatorAccount, err := crypto.AccountFromPrivateKey(appCreatorPrivateKey)
		if err != nil {
			log.Errorf("error in crypto.AccountFromPrivateKey: %v", err)
			return
		}

		suggestedParams, err := daemon.GetSuggestedParams(algodClient)
		if err != nil {
			log.Errorf("error getting suggested params from algod: %v", err)
			return
		}

		log.Info("creating dummy app...")
		dummyApprovalBytes, dummyClearBytes, err := daemon.CompileTeal(dummyAppApprovalFilename, dummyAppClearFilename, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		dummyAppID, err := daemon.DeployDummyApp(dummyApprovalBytes, dummyClearBytes, appCreatorPrivateKey, algodClient,
			suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("dummy app id: %d\n", dummyAppID)
		log.Info("creating ABI app...")
		approvalBytes, clearBytes, err := daemon.CompileTeal(approvalProgramFilename, clearProgramFilename, algodClient)
		if err != nil {
			log.Error(err)
			return
		}
		vrfProof, err := base64.StdEncoding.DecodeString(vrfProofString)
		if err != nil {
			log.Error(err)
			return
		}
		vrfPKAddr, err := types.DecodeAddress(vrfPKAddrString)
		if err != nil {
			log.Error(err)
			return
		}
		appID, err := daemon.DeployABIApp(
			startingRound, dummyAppID, algodClient, vrfPKAddr[:], appCreatorAccount, vrfProof, approvalBytes, clearBytes, suggestedParams)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("app id: %d\n", appID)

	},
}
