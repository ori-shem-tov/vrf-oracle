package main

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(runDaemonCmd)
	rootCmd.AddCommand(testCmd)
}

var rootCmd = &cobra.Command{
	Use:   "vrf-oracle",
	Short: "service that reads VRF requests from the blockchain, and broadcasts back the response",
	Run: func(cmd *cobra.Command, args []string) {
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}


func main() {
	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}
}