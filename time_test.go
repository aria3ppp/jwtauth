package jwtauth_test

import (
	"testing"
	"time"

	"github.com/aria3ppp/jwtauth"
	"github.com/stretchr/testify/require"
)

func TestTimeClock(t *testing.T) {
	require := require.New(t)

	var timeClock jwtauth.TimeClock

	t0 := time.Now()
	timeNow := timeClock.Now()
	t1 := time.Now()

	require.GreaterOrEqual(timeNow, t0)
	require.LessOrEqual(timeNow, t1)
}
