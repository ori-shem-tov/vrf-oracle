package test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/future"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/algorand/go-algorand-sdk/types"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io/ioutil"
)

var (
	appCreatorMnemonic         string
	approvalProgramFilename string
	clearProgramFilename string
	ownerAddrString string
	vrfServiceAddrString string
	signingPKString string
	shouldCreateDummy bool
)

func init() {
	daemon.SetLogger()

	createAppCmd.Flags().StringVar(&appCreatorMnemonic, "app-creator-mnemonic", "", "25-word mnemonic of the app creator")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "app-creator-mnemonic")

	createAppCmd.Flags().StringVar(&approvalProgramFilename, "approval-program", "", "TEAL script of the approval program")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "approval-program")

	createAppCmd.Flags().StringVar(&clearProgramFilename, "clear-program", "", "TEAL script of the clear program")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "clear-program")

	createAppCmd.Flags().StringVar(&ownerAddrString, "owner", "",
		"the address of the owner receiving the fees")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "owner")

	createAppCmd.Flags().StringVar(&vrfServiceAddrString, "vrf-service-addr", "",
		"the address of the VRF service account submitting responses to the blockchain")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "vrf-service-addr")

	createAppCmd.Flags().StringVar(&signingPKString, "signing-pk-addr", "",
		"the public key used to sign VRF responses (expected as an address with checksum)")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "signing-pk-addr")

	createAppCmd.Flags().Uint64Var(&fee, "fee", 0,
		"service fee")
	daemon.MarkFlagRequired(createAppCmd.Flags(), "fee")

	createAppCmd.Flags().BoolVar(&shouldCreateDummy, "should-create-dummy", false, "pass if a dummy app is also needed")
}

func generateAppArgsSlice(owner, vrfService, signingPK types.Address, fee uint64) [][]byte {
	feeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(feeBytes, fee)
	return [][]byte{
		owner[:],
		vrfService[:],
		signingPK[:],
		feeBytes,
	}
}

func generateSignedAppCreate(approvalBytes, clearBytes []byte, globalState, localState types.StateSchema,
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

func createApp(approvalProgram, clearProgram []byte, appCreatorSK ed25519.PrivateKey, owner, service, signingPK types.Address, fee uint64,
	algodClient *algod.Client, suggestedParams types.SuggestedParams) (uint64, error) {
	
	globalStateSchema := types.StateSchema{
		NumUint:      2,
		NumByteSlice: 3,
	}

	localStateSchema := types.StateSchema{
		NumUint:      1,
		NumByteSlice: 2,
	}

	appArgs := generateAppArgsSlice(owner, service, signingPK, fee)
	
	stxBytes, err := generateSignedAppCreate(approvalProgram, clearProgram, globalStateSchema,
		localStateSchema, appCreatorSK, appArgs, suggestedParams)
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

func createDummyApp(approvalProgram []byte, appCreatorSK ed25519.PrivateKey, algodClient *algod.Client,
	suggestedParams types.SuggestedParams) (uint64, error) {
	stxBytes, err := generateSignedAppCreate(approvalProgram, approvalProgram, types.StateSchema{},
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

var createAppCmd = &cobra.Command{
	Use:   "create-app",
	Short: "create the game app",
	Run: func(cmd *cobra.Command, args []string) {
		err := daemon.TestEnvironmentVariables()
		if err != nil {
			log.Error(err)
			return
		}
		algodClient, _, err := daemon.InitClients(daemon.AlgodAddress, daemon.AlgodToken, daemon.IndexerAddress, daemon.IndexerToken)
		if err != nil {
			log.Error(err)
			return
		}
		appCreatorSK, err := mnemonic.ToPrivateKey(appCreatorMnemonic)
		if err != nil {
			log.Error(err)
			return
		}

		owner, err := types.DecodeAddress(ownerAddrString)
		if err != nil {
			log.Error(err)
			return
		}
		vrfService, err := types.DecodeAddress(vrfServiceAddrString)
		if err != nil {
			log.Error(err)
			return
		}
		signingPKAddr, err := types.DecodeAddress(signingPKString)
		if err != nil {
			log.Error(err)
			return
		}

		approvalBytes, clearBytes, err := compileTeal(approvalProgramFilename, clearProgramFilename, algodClient)
		if err != nil {
			log.Error(err)
			return
		}

		approvalHashAddr := crypto.AddressFromProgram(approvalBytes)

		sp, err := algodClient.SuggestedParams().Do(context.Background())
		if err != nil {
			log.Error(err)
			return
		}

		appID, err := createApp(approvalBytes, clearBytes, appCreatorSK, owner, vrfService, signingPKAddr, fee, algodClient, sp)

		if err != nil {
			log.Error(err)
			return
		}
		fmt.Printf("app id: %d\napproval hash: %s\n", appID, approvalHashAddr)
		appAddress := crypto.GetApplicationAddress(appID)
		fmt.Printf("app address: %s\n", appAddress)
		fmt.Println("please fund to meet the minimum balance requirement")
		if shouldCreateDummy {
			dummyAppID, err := createDummyApp([]byte{0x05, 0x20, 0x01, 0x01, 0x22}, appCreatorSK, algodClient, sp)
			if err != nil {
				log.Error(err)
				return
			}
			fmt.Printf("dummy app id: %d\n", dummyAppID)
		}
	},
}


