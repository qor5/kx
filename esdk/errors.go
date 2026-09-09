package esdk

import (
	"context"
	stderrors "errors"
	"net"

	mpltypes "github.com/aws/aws-cryptographic-material-providers-library/releases/go/mpl/awscryptographymaterialproviderssmithygeneratedtypes"
	esdktypes "github.com/aws/aws-encryption-sdk/releases/go/encryption-sdk/awscryptographyencryptionsdksmithygeneratedtypes"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/pkg/errors"

	"github.com/qor5/kx/api"
)

// classifyDecryptError maps an Encryption SDK failure onto kx's error contract.
//
// Callers distinguish "this ciphertext cannot be decrypted" from "KMS is
// unreachable or refused us" — the former is a data problem tied to one row, the
// latter is an outage or a misconfiguration affecting every row. awskms gets
// that distinction from a single typed KMS exception; the Encryption SDK reports
// everything through several untyped shapes instead, so the split has to be
// reconstructed here.
func classifyDecryptError(err error) error {
	// A KMS InvalidCiphertextException means the wrapped data key does not
	// belong to this key or the encryption context did not match.
	var invalidCiphertext *kmstypes.InvalidCiphertextException
	if walkErrors(err, func(e error) bool { return stderrors.As(e, &invalidCiphertext) }) {
		return errors.WithStack(&api.InvalidCiphertextError{Err: err})
	}

	// Anything that went wrong while talking to KMS is an infrastructure
	// condition. Surface it unchanged so retry and alerting logic upstream can
	// still see it, and so a KMS blip is never recorded against a row as a
	// ciphertext beyond repair.
	if walkErrors(err, isTransportFailure) {
		return errors.WithStack(err)
	}

	// Otherwise the failure came from the Encryption SDK's own parsing or
	// authentication of the message: a corrupt ciphertext, or an encryption
	// context that does not match the one the message was sealed with.
	return errors.WithStack(&api.InvalidCiphertextError{Err: err})
}

// isTransportFailure reports whether e is a failure of the call to KMS rather
// than of the message being decrypted.
//
// smithy.OperationError is what makes the judgement possible: the AWS SDK wraps
// every call it makes in one, so finding it means the failure happened on the
// KMS round trip rather than in the Encryption SDK's own reading of the message.
// The remaining checks catch failures that never reach that wrapper — a dead
// connection, or a context cancelled while the batch was in flight.
//
// Without this, awskms's behaviour would silently change: it reports only KMS's
// own InvalidCiphertextException as an invalid ciphertext and passes everything
// else through, so a caller treating api.InvalidCiphertextError as "this row is
// unrecoverable" stays correct during an outage. Falling through to the
// Encryption SDK's catch-all would break that for every transport error.
func isTransportFailure(e error) bool {
	var apiErr smithy.APIError
	var opErr *smithy.OperationError
	var netErr net.Error
	return stderrors.As(e, &apiErr) ||
		stderrors.As(e, &opErr) ||
		stderrors.As(e, &netErr) ||
		stderrors.Is(e, context.Canceled) ||
		stderrors.Is(e, context.DeadlineExceeded)
}

// walkErrors reports whether fn matches err or anything nested inside it.
//
// The Encryption SDK and the material-providers library each define their own
// CollectionOfErrors and OpaqueError. Neither implements Unwrap, so errors.As
// alone cannot see through them and the nesting has to be walked explicitly.
func walkErrors(err error, fn func(error) bool) bool {
	for e := err; e != nil; e = stderrors.Unwrap(e) {
		if fn(e) {
			return true
		}
		for _, nested := range nestedErrors(e) {
			if walkErrors(nested, fn) {
				return true
			}
		}
	}
	return false
}

// nestedErrors returns the errors carried inside the Encryption SDK's container
// error types, which are opaque to errors.Unwrap.
func nestedErrors(err error) []error {
	switch t := err.(type) {
	case esdktypes.CollectionOfErrors:
		return t.ListOfErrors
	case mpltypes.CollectionOfErrors:
		return t.ListOfErrors
	case esdktypes.OpaqueError:
		return errorSlice(t.ErrObject)
	case mpltypes.OpaqueError:
		return errorSlice(t.ErrObject)
	}
	return nil
}

func errorSlice(v interface{}) []error {
	if e, ok := v.(error); ok {
		return []error{e}
	}
	return nil
}
