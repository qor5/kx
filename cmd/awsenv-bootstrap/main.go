package main

import (
	"context"
	"fmt"
	"os"

	"github.com/qor5/kx/awsenv"
)

// awsenv-bootstrap ensures AWS credentials are available by managing the root-level .aws.env file.
// Configuration is controlled via environment variables (see awsenv.Ensure docs).
func main() {
	if err := awsenv.Ensure(context.Background()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
