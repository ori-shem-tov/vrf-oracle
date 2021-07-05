module github.com/ori-shem-tov/vrf-oracle

go 1.14

require (
	github.com/algorand/go-algorand-sdk v1.8.0
	github.com/algorandfoundation/go-aftools v0.0.0-00010101000000-000000000000
	github.com/ori-shem-tov/vrf-oracle/tools v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
)

replace github.com/algorandfoundation/go-aftools => ./private/github.com/algorandfoundation/go-aftools
replace github.com/ori-shem-tov/vrf-oracle/tools => ./tools
