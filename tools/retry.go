package tools

import (
	"fmt"
	"time"
)

type ActionFunc = func() error
type LogFunc = func(error)

// Retry implements an exponential backoff retry mechanism where:
// `initWaitDuration` is the initial number of seconds you wait for (recommended = 1)
// `retries` is the maximum number of executions
// `action` is the function to execute
// `log` is the function to log errors occurred in each retry
func Retry(initWaitSeconds int, retries int, action ActionFunc, log LogFunc) error {
	var err error
	timeToSleep := initWaitSeconds
	for i := 0; i < retries; i++ {
		if timeToSleep <= 0 {
			return fmt.Errorf(
				"number of seconds has become negative (%d) in try %d"+
					"(most likely a bug in arguments of Retry(%d, %d, ...))",
				timeToSleep, i,
				initWaitSeconds, retries,
			)
		}
		err = action()
		if err == nil {
			return nil
		}
		log(err)
		time.Sleep(time.Second * time.Duration(timeToSleep))
		timeToSleep *= 2
	}
	return err
}
