package esdk

import (
	stderrors "errors"

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
// everything through three untyped shapes instead, so the split has to be
// reconstructed here.
func classifyDecryptError(err error) error {
	// A KMS InvalidCiphertextException means the wrapped data key does not
	// belong to this key or the encryption context did not match.
	var invalidCiphertext *kmstypes.InvalidCiphertextException
	if walkErrors(err, func(e error) bool { return stderrors.As(e, &invalidCiphertext) }) {
		return errors.WithStack(&api.InvalidCiphertextError{Err: err})
	}

	// Any other modelled service error (AccessDenied, Throttling, KMSInvalidState,
	// …) is an infrastructure condition. Surface it unchanged so retry and
	// alerting logic upstream can still see it.
	var apiErr smithy.APIError
	if walkErrors(err, func(e error) bool { return stderrors.As(e, &apiErr) }) {
		return errors.WithStack(err)
	}

	// Otherwise the failure came from the Encryption SDK's own parsing or
	// authentication of the message: a corrupt ciphertext, or an encryption
	// context that does not match the one the message was sealed with.
	return errors.WithStack(&api.InvalidCiphertextError{Err: err})
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
