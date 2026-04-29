package main

import (
    "github.com/The-17/keychain-auth/internal/cli"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// entry point
func main() {
	cli.Execute(version)
}
