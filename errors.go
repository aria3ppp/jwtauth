package jwtauth

import "errors"

var (
	ErrInvalidKid = errors.New("invalid kid")
	ErrUnsetKid   = errors.New("unset kid")
)
