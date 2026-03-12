package awsenv

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	godotenv "github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/samber/lo"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const defaultTimeout = 10 * time.Second

// Option configures the behavior of Ensure.
type Option func(*options)

type options struct {
	timeout time.Duration
}

// WithTimeout sets the overall timeout for Ensure. Default is 10s.
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		o.timeout = d
	}
}

// Ensure makes sure AWS credentials are available in the current process.
// It guarantees reading/writing `.aws.env` only at the project root (module dir from `go list`),
// validates credentials via STS, and refreshes them via `oidc2aws` if needed.
// The behavior can be controlled via environment variables:
//   - QOR_PROJECT_ROOT: force project root directory
//   - QOR_AWSENV_FILE: file name at root (default: .aws.env)
//   - QOR_AWS_REGION: AWS region to write if refreshing (default: ap-northeast-1)
//   - QOR_OIDC2AWS_ALIAS: oidc2aws alias (default: qor5-test)
//   - QOR_AWSENV_FORCE_REFRESH: if true-like, force refresh even if valid
func Ensure(ctx context.Context, opts ...Option) error {
	// Skip entirely in GitHub CI environments
	if strings.EqualFold(strings.TrimSpace(os.Getenv("GITHUB_ACTIONS")), "true") {
		return nil
	}

	o := &options{timeout: defaultTimeout}
	for _, opt := range opts {
		opt(o)
	}

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	result := make(chan error, 1)
	go func() {
		result <- doEnsure(ctx)
	}()

	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return errors.Errorf("awsenv.Ensure timed out after %s: your network connection may have issues or AWS/oidc2aws services are unreachable", o.timeout)
	}
}

func doEnsure(ctx context.Context) error {
	projectRoot, err := detectProjectRoot(ctx)
	if err != nil {
		return err
	}

	envFileName := lo.Ternary(strings.TrimSpace(os.Getenv("QOR_AWSENV_FILE")) == "", ".aws.env", os.Getenv("QOR_AWSENV_FILE"))
	envFilePath := filepath.Join(projectRoot, envFileName)

	forceRefresh := isTruthy(os.Getenv("QOR_AWSENV_FORCE_REFRESH"))

	if !forceRefresh {
		// Best-effort: load and validate first without taking the lock
		_ = godotenv.Overload(envFilePath)
		if err := validateAWSCredentials(ctx); err == nil {
			return nil
		}
	}

	lockPath := envFilePath + ".lock"
	fileLock := flock.New(lockPath)
	// Try to acquire lock with context so it respects the timeout
	locked, err := fileLock.TryLockContext(ctx, 200*time.Millisecond)
	if err != nil {
		return errors.WithMessage(err, "failed to acquire awsenv lock")
	}
	if !locked {
		return errors.New("failed to acquire awsenv lock: context cancelled")
	}
	defer func() {
		_ = fileLock.Unlock()
	}()

	// Re-check after acquiring lock to avoid redundant refreshes
	if !forceRefresh {
		_ = godotenv.Overload(envFilePath)
		if err := validateAWSCredentials(ctx); err == nil {
			return nil
		}
	}

	alias := lo.Ternary(strings.TrimSpace(os.Getenv("QOR_OIDC2AWS_ALIAS")) == "", "qor5-test", os.Getenv("QOR_OIDC2AWS_ALIAS"))
	region := lo.Ternary(strings.TrimSpace(os.Getenv("QOR_AWS_REGION")) == "", "ap-northeast-1", os.Getenv("QOR_AWS_REGION"))

	content, err := runOidc2aws(ctx, alias)
	if err != nil {
		return err
	}

	newEnvContent := buildEnvFileContent(content, region)
	if err := atomicWriteFile(envFilePath, []byte(newEnvContent), 0o644); err != nil {
		return err
	}

	if err := godotenv.Overload(envFilePath); err != nil {
		return errors.WithStack(err)
	}
	if err := validateAWSCredentials(ctx); err != nil {
		return err
	}
	return nil
}

// detectProjectRoot gets the main module directory using the Go toolchain.
// Order: QOR_PROJECT_ROOT override -> `go list -m -f {{.Dir}}` -> error if empty/failed.
func detectProjectRoot(ctx context.Context) (string, error) {
	if root := strings.TrimSpace(os.Getenv("QOR_PROJECT_ROOT")); root != "" {
		if stat, err := os.Stat(root); err == nil && stat.IsDir() {
			return root, nil
		}
		return "", errors.New("QOR_PROJECT_ROOT is not a valid directory")
	}

	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Dir}}")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", errors.WithMessage(err, "failed to resolve project root via 'go list -m'")
	}
	dir := strings.TrimSpace(stdout.String())
	if dir == "" {
		return "", errors.New("project root is empty from 'go list -m'; set QOR_PROJECT_ROOT")
	}
	if stat, err := os.Stat(dir); err != nil || !stat.IsDir() {
		return "", errors.New("project root resolved by 'go list -m' is not a directory")
	}
	return dir, nil
}

// validateAWSCredentials loads default AWS config and calls STS GetCallerIdentity.
func validateAWSCredentials(ctx context.Context) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errors.WithMessage(err, "failed to load AWS config")
	}
	client := sts.NewFromConfig(cfg)
	_, err = client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return errors.WithMessage(err, "AWS credentials validation failed")
	}
	return nil
}

// runOidc2aws executes `oidc2aws -login -alias <alias> --env` and returns its stdout.
func runOidc2aws(ctx context.Context, alias string) (string, error) {
	cmd := exec.CommandContext(ctx, "oidc2aws", "-login", "-alias", alias, "--env")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", errors.WithMessage(err, "oidc2aws command failed")
	}
	return strings.TrimSpace(stdout.String()), nil
}

// buildEnvFileContent appends region/config flags to the oidc2aws output.
func buildEnvFileContent(base string, region string) string {
	var b strings.Builder
	if strings.TrimSpace(base) != "" {
		b.WriteString(strings.TrimSpace(base))
		b.WriteByte('\n')
	}
	b.WriteString("export AWS_REGION='")
	b.WriteString(region)
	b.WriteString("'\n")
	b.WriteString("export AWS_SDK_LOAD_CONFIG=1\n")
	return b.String()
}

// atomicWriteFile writes to a temp file then renames it to the target path.
func atomicWriteFile(targetPath string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	tmpFile, err := os.CreateTemp(dir, ".aws.env.*.tmp")
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	writer := bufio.NewWriter(tmpFile)
	if _, err := writer.Write(content); err != nil {
		_ = tmpFile.Close()
		return errors.WithStack(err)
	}
	if err := writer.Flush(); err != nil {
		_ = tmpFile.Close()
		return errors.WithStack(err)
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return errors.WithStack(err)
	}
	if err := tmpFile.Close(); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Rename(tmpFile.Name(), targetPath); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// isTruthy checks typical truthy values.
func isTruthy(val string) bool {
	s := strings.ToLower(strings.TrimSpace(val))
	if s == "" {
		return false
	}
	truthy := map[string]struct{}{
		"1": {}, "t": {}, "true": {}, "y": {}, "yes": {}, "on": {},
	}
	_, ok := truthy[s]
	return ok
}
