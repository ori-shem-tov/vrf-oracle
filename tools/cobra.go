package tools

import (
	"fmt"
	"github.com/algorand/go-algorand-sdk/client/v2/algod"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"strings"
)

func MarkFlagRequired(flag *pflag.FlagSet, name string) {
	err := cobra.MarkFlagRequired(flag, name)
	if err != nil {
		panic(err)
	}
}

func SetLogger(logLevelEnv string) {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	logLevel := log.WarnLevel
	if logLevelEnv == "debug" {
		logLevel = log.DebugLevel
	} else if logLevelEnv == "info" {
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
}

func TestEnvironmentVariables(AlgodAddress string) error {
	var missing []string
	if AlgodAddress == "" {
		missing = append(missing, "AF_ALGOD_ADDRESS")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s environment variable(s)", strings.Join(missing, ","))
	}
	return nil
}

func InitClients(algodAddress, algodToken string) (*algod.Client, error) {
	var failedClients []string
	algodClient, err := algod.MakeClient(algodAddress, algodToken)
	if err != nil {
		failedClients = append(failedClients, "algod")
		log.Error(err)
	}
	if len(failedClients) > 0 {
		err = fmt.Errorf("failed creating the following client(s): %s", strings.Join(failedClients, ","))
	}
	return algodClient, err
}
