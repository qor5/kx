package esdk

import (
	"context"
	"sort"
	"strings"
	"sync"

	mplclient "github.com/aws/aws-cryptographic-material-providers-library/releases/go/mpl/awscryptographymaterialproviderssmithygenerated"
	mpltypes "github.com/aws/aws-cryptographic-material-providers-library/releases/go/mpl/awscryptographymaterialproviderssmithygeneratedtypes"
	esdkclient "github.com/aws/aws-encryption-sdk/releases/go/encryption-sdk/awscryptographyencryptionsdksmithygenerated"
	esdktypes "github.com/aws/aws-encryption-sdk/releases/go/encryption-sdk/awscryptographyencryptionsdksmithygeneratedtypes"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/pkg/errors"
	"github.com/theplant/appkit/logtracing"

	"github.com/qor5/kx/api"
	"github.com/qor5/kx/awskms"
)

// CipherFactory encrypts with the AWS Encryption SDK and decrypts both the
// Encryption SDK format and the bare KMS format written by awskms.
//
// The returned CipherFactory is safe for concurrent use by multiple goroutines.
type CipherFactory struct {
	keyID string

	esdkClient *esdkclient.Client
	mplClient  *mplclient.Client
	keyring    mpltypes.IKeyring

	// defaultCMM wraps keyring. CreateRequiredEncryptionContextCMM rejects a
	// bare keyring ("currently only supports cmm") despite its input struct
	// exposing a Keyring field, so the required-context manager has to be
	// layered on top of this one.
	defaultCMM mpltypes.ICryptographicMaterialsManager

	// legacy reads (and, until envelopeWrite is enabled, writes) bare KMS
	// ciphertexts. Reusing awskms rather than reimplementing it keeps the
	// legacy path byte-for-byte identical to what is already in production.
	legacy *awskms.CipherFactory

	envelopeWrite bool
	signing       bool

	// cmms memoises one materials manager per set of encryption-context keys.
	// Construction is local but not free, and in practice a process sees only a
	// handful of distinct key sets (one per registered struct).
	cmms sync.Map // string -> mpltypes.ICryptographicMaterialsManager
}

// NewCipherFactory returns a CipherFactory that wraps the AWS KMS key with the
// given keyID.
//
// The caller is responsible for ensuring that keyID refers to a symmetric
// encryption key in AWS KMS.
//
// By default the factory still writes bare KMS ciphertexts; pass
// WithEnvelopeWrite(true) to start writing envelope ciphertexts. Decryption
// always accepts both formats regardless of that setting.
func NewCipherFactory(cfg aws.Config, keyID string, opts ...Option) (*CipherFactory, error) {
	if len(keyID) == 0 {
		return nil, errors.New("keyID is required")
	}

	legacy, err := awskms.NewCipherFactory(cfg, keyID)
	if err != nil {
		return nil, err
	}

	mplc, err := mplclient.NewClient(mpltypes.MaterialProvidersConfig{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create material providers client")
	}

	keyring, err := mplc.CreateAwsKmsKeyring(context.Background(), mpltypes.CreateAwsKmsKeyringInput{
		KmsClient: kms.NewFromConfig(cfg),
		KmsKeyId:  keyID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create kms keyring")
	}

	defaultCMM, err := mplc.CreateDefaultCryptographicMaterialsManager(context.Background(),
		mpltypes.CreateDefaultCryptographicMaterialsManagerInput{Keyring: keyring})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create default cryptographic materials manager")
	}

	commitmentPolicy := mpltypes.ESDKCommitmentPolicyRequireEncryptRequireDecrypt
	esdkc, err := esdkclient.NewClient(esdktypes.AwsEncryptionSdkConfig{
		CommitmentPolicy: &commitmentPolicy,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create encryption sdk client")
	}

	f := &CipherFactory{
		keyID:      keyID,
		esdkClient: esdkc,
		mplClient:  mplc,
		keyring:    keyring,
		defaultCMM: defaultCMM,
		legacy:     legacy,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f, nil
}

var _ api.CipherFactory = (*CipherFactory)(nil)

func (f *CipherFactory) NewEncrypter() api.Encrypter {
	return f
}

func (f *CipherFactory) NewDecrypter() api.Decrypter {
	return f
}

func (f *CipherFactory) Encrypt(
	ctx context.Context, plaintext []byte, encryptionContext map[string]string,
) (ciphertext []byte, err error) {
	if !f.envelopeWrite {
		return f.legacy.Encrypt(ctx, plaintext, encryptionContext)
	}

	f.appendSpanKVs(ctx, encryptionContext)
	logtracing.AppendSpanKVs(ctx, "kms.envelope", true)

	cmm, err := f.materialsManager(ctx, encryptionContext)
	if err != nil {
		return nil, err
	}

	suite := f.algorithmSuiteID()
	in := esdktypes.EncryptInput{
		Plaintext:         plaintext,
		EncryptionContext: encryptionContext,
		AlgorithmSuiteId:  &suite,
	}
	if cmm != nil {
		in.MaterialsManager = cmm
	} else {
		in.Keyring = f.keyring
	}

	out, err := f.esdkClient.Encrypt(ctx, in)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt data")
	}
	return addEnvelopePrefix(out.Ciphertext), nil
}

func (f *CipherFactory) Decrypt(
	ctx context.Context, ciphertext []byte, encryptionContext map[string]string,
) (plaintext []byte, err error) {
	if !hasEnvelopePrefix(ciphertext) {
		return f.legacy.Decrypt(ctx, ciphertext, encryptionContext)
	}

	f.appendSpanKVs(ctx, encryptionContext)
	logtracing.AppendSpanKVs(ctx, "kms.envelope", true)

	cmm, err := f.materialsManager(ctx, encryptionContext)
	if err != nil {
		return nil, err
	}

	in := esdktypes.DecryptInput{
		Ciphertext:        stripEnvelopePrefix(ciphertext),
		EncryptionContext: encryptionContext,
	}
	if cmm != nil {
		in.MaterialsManager = cmm
	} else {
		in.Keyring = f.keyring
	}

	out, err := f.esdkClient.Decrypt(ctx, in)
	if err != nil {
		return nil, classifyDecryptError(err)
	}
	return out.Plaintext, nil
}

// algorithmSuiteID returns the suite to encrypt with. Both options commit to the
// data key, as REQUIRE_ENCRYPT_REQUIRE_DECRYPT demands; see WithSigning for why
// the unsigned one is the default. Decryption never consults this — the suite is
// recorded in each message, so messages written under either one stay readable.
func (f *CipherFactory) algorithmSuiteID() mpltypes.ESDKAlgorithmSuiteId {
	if f.signing {
		return mpltypes.ESDKAlgorithmSuiteIdAlgAes256GcmHkdfSha512CommitKeyEcdsaP384
	}
	return mpltypes.ESDKAlgorithmSuiteIdAlgAes256GcmHkdfSha512CommitKey
}

// materialsManager returns a materials manager that binds every
// encryption-context entry into the message's authenticated data without
// storing it in the message header.
//
// This is what preserves the guarantee awskms got for free from kms:Decrypt:
// the encryption context supplied on decrypt must match the one used on
// encrypt, so a ciphertext lifted from another row does not decrypt. The
// Encryption SDK's default behaviour is weaker — it stores the context in the
// header and hands it back to the caller without comparing it — so relying on
// the default would silently drop kx's row-level binding.
//
// A nil manager means the context is empty and the keyring can be used directly.
func (f *CipherFactory) materialsManager(
	ctx context.Context, encryptionContext map[string]string,
) (mpltypes.ICryptographicMaterialsManager, error) {
	if len(encryptionContext) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(encryptionContext))
	for k := range encryptionContext {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	cacheKey := strings.Join(keys, "\x00")
	if cached, ok := f.cmms.Load(cacheKey); ok {
		return cached.(mpltypes.ICryptographicMaterialsManager), nil
	}

	cmm, err := f.mplClient.CreateRequiredEncryptionContextCMM(ctx, mpltypes.CreateRequiredEncryptionContextCMMInput{
		RequiredEncryptionContextKeys: keys,
		UnderlyingCMM:                 f.defaultCMM,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create required encryption context cmm")
	}

	actual, _ := f.cmms.LoadOrStore(cacheKey, cmm)
	return actual.(mpltypes.ICryptographicMaterialsManager), nil
}

func (f *CipherFactory) appendSpanKVs(ctx context.Context, encryptionContext map[string]string) {
	logtracing.AppendSpanKVs(ctx,
		"span.type", "aws.kms",
		"span.role", "client",
		"kms.key_id", f.keyID,
	)
	var kvs []interface{}
	for k, v := range encryptionContext {
		kvs = append(kvs, "kms.enc_ctx."+k, v)
	}
	logtracing.AppendSpanKVs(ctx, kvs...)
}
