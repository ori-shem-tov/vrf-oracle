package test

import (
	"github.com/spf13/cobra"
)

func init() {
	TestCmd.AddCommand(requestCmd)
	TestCmd.AddCommand(createAppCmd)
	TestCmd.AddCommand(cancelCmd)
	TestCmd.AddCommand(withdrawLostFundsCmd)
	//TestCmd.AddCommand(EndToEndCmd)
}

var TestCmd = &cobra.Command{
	Use:   "test",
	Short: "test tool for the vrf daemon",
	Run: func(cmd *cobra.Command, args []string) {
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}
