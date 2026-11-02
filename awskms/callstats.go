package awskms

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go/middleware"
	"github.com/theplant/appkit/logtracing"
)

// callStats observes a single KMS API call from inside the SDK middleware
// stack, capturing the time the span duration alone cannot break down:
// how many attempts the retryer made, why the first one failed, and how long
// was spent waiting for credentials.
//
// Credential wait matters because the SDK's credentials cache refreshes
// lazily: the first call after the cached credentials expire blocks on the
// provider (an STS round-trip under IRSA), and concurrent callers wait on the
// same refresh.
//
// A callStats must be used for exactly one API call; attempts of one call run
// sequentially, so no locking is needed.
type callStats struct {
	attempts      int
	firstErr      error
	identityWait  time.Duration
	identityStart time.Time
}

// withStats is a per-call option that installs the observing middlewares.
func (s *callStats) withStats(o *kms.Options) {
	o.APIOptions = append(o.APIOptions, s.addMiddlewares)
}

func (s *callStats) addMiddlewares(stack *middleware.Stack) error {
	// Inserted after "Retry", so it runs once per attempt.
	if err := stack.Finalize.Insert(middleware.FinalizeMiddlewareFunc("kx.CountAttempt", s.countAttempt), "Retry", middleware.After); err != nil {
		return err
	}
	if err := stack.Finalize.Insert(middleware.FinalizeMiddlewareFunc("kx.IdentityStart", s.identityStarted), "GetIdentity", middleware.Before); err != nil {
		return err
	}
	return stack.Finalize.Insert(middleware.FinalizeMiddlewareFunc("kx.IdentityEnd", s.identityResolved), "GetIdentity", middleware.After)
}

func (s *callStats) countAttempt(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	s.attempts++
	out, md, err := next.HandleFinalize(ctx, in)
	if err != nil && s.firstErr == nil {
		s.firstErr = err
	}
	return out, md, err
}

func (s *callStats) identityStarted(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	s.identityStart = time.Now()
	return next.HandleFinalize(ctx, in)
}

func (s *callStats) identityResolved(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	s.identityWait += time.Since(s.identityStart)
	return next.HandleFinalize(ctx, in)
}

// appendSpanKVs records the stats on the span in ctx. The first attempt's
// error is recorded only when the call was retried; a call that failed on its
// only attempt already carries that error as the span error.
func (s *callStats) appendSpanKVs(ctx context.Context) {
	kvs := []any{
		"kms.attempts", s.attempts,
		"kms.identity_ms", float64(s.identityWait.Microseconds()) / 1000,
	}
	if s.attempts > 1 && s.firstErr != nil {
		kvs = append(kvs, "kms.first_attempt_err", s.firstErr.Error())
	}
	logtracing.AppendSpanKVs(ctx, kvs...)
}
