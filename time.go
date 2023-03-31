package jwtauth

import "time"

type Clock interface {
	Now() time.Time
}

type TimeClock struct{}

var _ Clock = TimeClock{}

func (t TimeClock) Now() time.Time {
	return time.Now()
}
