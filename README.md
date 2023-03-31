# jwtauth
[![Tests](https://github.com/aria3ppp/jwtauth/actions/workflows/tests.yml/badge.svg)](https://github.com/aria3ppp/jwtauth/actions/workflows/tests.yml)
[![Coverage Status](https://coveralls.io/repos/github/aria3ppp/jwtauth/badge.svg?branch=master)](https://coveralls.io/github/aria3ppp/jwtauth?branch=master)

`jwtauth` handle multiple keys for jwt token signing and verification. 
It also support key deprecation and backward compatibility for verifying old tokens.
Tokens are signed by choosing a random key that is not marked as deprecated. Deprecated keys can only verify old tokens and not sign new ones.
