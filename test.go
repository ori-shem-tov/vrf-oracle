package main

import (
	"github.com/spf13/cobra"
)

func init() {
	testCmd.AddCommand(queryPhaseCmd)
	testCmd.AddCommand(createAppCmd)
	testCmd.AddCommand(settlementPhaseCmd)
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "test tool for the vrf daemon",
	Run: func(cmd *cobra.Command, args []string) {
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}
