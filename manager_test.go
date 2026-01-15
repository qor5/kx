package kx_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/qor5/kx"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"

	"github.com/qor5/kx/api"
	"github.com/qor5/kx/api/mock"
	"github.com/qor5/kx/xhmac"
)

var ctx = context.Background()

func getHashKey(t *testing.T) []byte {
	key := make([]byte, sha256.Size)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestNewManager(t *testing.T) {
	registry, err := kx.NewRegistry()
	require.NoError(t, err)
	cipherFactory := mock.NewCipherFactory()
	hashKey := getHashKey(t)
	hashFactory, err := xhmac.NewHashFactory(hashKey)
	require.NoError(t, err)

	tests := []struct {
		name          string
		cipherFactory api.CipherFactory
		hashFactory   api.HashFactory
		registry      *kx.Registry
		wantErr       string
	}{
		{
			name:          "valid configuration",
			cipherFactory: cipherFactory,
			hashFactory:   hashFactory,
			registry:      registry,
		},
		{
			name:          "nil registry",
			cipherFactory: cipherFactory,
			hashFactory:   hashFactory,
			registry:      nil,
			wantErr:       "registry is required",
		},
		{
			name:          "nil cipher factory",
			cipherFactory: nil,
			hashFactory:   hashFactory,
			registry:      registry,
			wantErr:       "cipher factory is required",
		},
		{
			name:          "nil hash factory",
			cipherFactory: cipherFactory,
			hashFactory:   nil,
			registry:      registry,
			wantErr:       "hash factory is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := kx.NewManager(tt.cipherFactory, tt.hashFactory, tt.registry)

			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, manager)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, manager)
		})
	}
}

func mustEncryptObj[T any](t *testing.T, obj T, m *kx.Manager) (T, string) {
	encrypted, ciphertext, err := kx.EncryptStruct(ctx, m, obj, nil)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	require.NotNil(t, encrypted)
	return encrypted, ciphertext
}

func mustDecryptObj[T any](t *testing.T, encrypted T, ciphertext string, m *kx.Manager) T {
	decrypted, err := kx.DecryptStruct(ctx, m, encrypted, ciphertext, nil)
	require.NoError(t, err)
	return decrypted
}

func TestManager(t *testing.T) {
	cipherFactory := mock.NewCipherFactory()
	hashKey := getHashKey(t)
	hashFactory, err := xhmac.NewHashFactory(hashKey)
	require.NoError(t, err)
	registry, err := kx.NewRegistry()
	require.NoError(t, err)
	mustNewManager := func(t *testing.T) *kx.Manager {
		manager, err := kx.NewManager(cipherFactory, hashFactory, registry)
		require.NoError(t, err)
		return manager
	}

	t.Run("invalid_input", func(t *testing.T) {
		manager := mustNewManager(t)

		// Test non-pointer input
		_, _, err := manager.EncryptStruct(ctx, "not a struct", nil)
		assert.Contains(t, err.Error(), "value must be a struct or pointer to struct, got string")

		_, err = manager.DecryptStruct(ctx, 42, "ciphertext", nil)
		assert.Contains(t, err.Error(), "value must be a struct or pointer to struct")

		_, err = manager.DecryptStruct(ctx, 20, "", nil)
		assert.Contains(t, err.Error(), "ciphertext is required")

		// Test Unregistered type
		type FooA struct {
			Field string
		}
		_, _, err = manager.EncryptStruct(ctx, &FooA{}, nil)
		assert.Contains(t, err.Error(), "no encryption configuration found")

		// Test pointer to non-struct
		var nonStruct *int
		_, _, err = manager.EncryptStruct(ctx, nonStruct, nil)
		assert.ErrorContains(t, err, "value must be a struct or pointer to struct, got *int")

		// TODO: storage field cannot set
	})

	t.Run("value_type_input", func(t *testing.T) {
		type ValueTypeStruct struct {
			Name       string
			HashedName string
		}
		registry.MustRegisterStruct(ValueTypeStruct{}, kx.WithRegularField("Name", true))
		manager := mustNewManager(t)

		// Test encrypt with value type (not pointer)
		original := ValueTypeStruct{
			Name: "test value",
		}
		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		assert.Equal(t, "test value", encrypted.Name) // Top-level fields are not cleared
		assert.NotEmpty(t, encrypted.HashedName)

		// Verify original is not modified
		assert.Equal(t, "test value", original.Name)

		// Test decrypt with value type
		decrypted, err := kx.DecryptStruct(ctx, manager, encrypted, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, "test value", decrypted.Name)
		assert.Equal(t, encrypted.HashedName, decrypted.HashedName)
	})

	t.Run("empty_encrypted_data", func(t *testing.T) {
		type BasicType struct {
			Field string
		}
		registry.MustRegisterStruct(BasicType{}, kx.WithRegularField("Field", false))
		manager := mustNewManager(t)
		// Test decryption with empty EncryptedData
		decrypted := &BasicType{
			Field: "field",
		}
		_, err := manager.DecryptStruct(ctx, decrypted, "ciphertext", nil)
		assert.ErrorContains(t, err, "illegal base64")
		assert.Equal(t, "field", decrypted.Field)
	})

	t.Run("encrypt_and_decrypt_complex_types_with_pointers", func(t *testing.T) {
		type ComplexWithPointers struct {
			BirthdayPtr       *Birthday
			HashedBirthdayPtr string
			Name              string
			HashedName        string
		}

		registry.MustRegisterStruct(ComplexWithPointers{},
			kx.WithRegularField("BirthdayPtr", true),
			kx.WithRegularField("Name", true),
		)
		manager := mustNewManager(t)

		// Test case 1: All fields with values
		birthday := Birthday{
			Time: time.Now(),
		}
		original1 := &ComplexWithPointers{
			BirthdayPtr: &birthday,
			Name:        "John Doe",
		}

		encrypted1, ciphertext1 := mustEncryptObj(t, original1, manager)

		// Verify hash fields are set
		assert.NotEmpty(t, encrypted1.HashedBirthdayPtr)
		assert.NotEmpty(t, encrypted1.HashedName)

		decrypted1 := mustDecryptObj(t, encrypted1, ciphertext1, manager)

		// Verify original values are preserved
		assert.NotNil(t, decrypted1.BirthdayPtr)
		assert.Equal(t, birthday.Unix(), decrypted1.BirthdayPtr.Unix())
		assert.Equal(t, "John Doe", decrypted1.Name)

		// Verify hash fields remain unchanged
		assert.Equal(t, encrypted1.HashedBirthdayPtr, decrypted1.HashedBirthdayPtr)
		assert.Equal(t, encrypted1.HashedName, decrypted1.HashedName)

		// Test case 2: Pointer field is nil
		original2 := &ComplexWithPointers{
			BirthdayPtr: nil,
			Name:        "Jane Doe",
		}

		encrypted2, ciphertext2 := mustEncryptObj(t, original2, manager)

		// Hash field for nil pointer that implements fmt.Stringer:
		// String() returns empty string, and hash of empty string is a non-empty hash value
		assert.NotEmpty(t, encrypted2.HashedBirthdayPtr) // *Birthday implements fmt.Stringer
		assert.NotEmpty(t, encrypted2.HashedName)

		decrypted2 := mustDecryptObj(t, encrypted2, ciphertext2, manager)

		assert.Nil(t, decrypted2.BirthdayPtr)
		assert.Equal(t, "Jane Doe", decrypted2.Name)

		// Verify hash fields remain unchanged
		assert.Equal(t, encrypted2.HashedBirthdayPtr, decrypted2.HashedBirthdayPtr)
		assert.Equal(t, encrypted2.HashedName, decrypted2.HashedName)
	})

	t.Run("encrypt_and_decrypt_map_with_json_paths", func(t *testing.T) {
		type MapStruct struct {
			Metadata []byte
		}

		registry.MustRegisterStruct(MapStruct{}, kx.WithJSONField("Metadata", []kx.JSONPathConfig{
			{Path: "sensitive.field1.value", Hash: false},
			{Path: "sensitive.field2.value", Hash: false},
		}))

		// Create the initial JSON data
		jsonBytes := []byte(`{"sensitive": {"field1": {"value": "secret1"}, "field2": {"value": "secret2"}}, "public": "not-secret"}`)

		// Convert to JSON bytes

		original := &MapStruct{
			Metadata: jsonBytes,
		}

		// Test encryption
		manager := mustNewManager(t)
		encrypted, ciphertext := mustEncryptObj(t, original, manager)
		assert.JSONEq(t, `{"public": "not-secret", "sensitive": {"field1": {}, "field2": {}}}`, string(encrypted.Metadata))

		decrypted := mustDecryptObj(t, encrypted, ciphertext, manager)
		assert.JSONEq(t, string(jsonBytes), string(decrypted.Metadata))
	})

	t.Run("encrypt_and_decrypt_complex_types", func(t *testing.T) {
		type NestedType struct {
			Key   string
			Value string
		}
		type ComplexTestStruct struct {
			ID         string
			Name       string
			CreatedAt  time.Time
			Numbers    []int
			Metadata   []byte
			NestedType NestedType
		}

		registry.MustRegisterStruct(ComplexTestStruct{},
			kx.WithRegularField("Name", false),
			kx.WithRegularField("CreatedAt", false),
			kx.WithRegularField("Numbers", false),
			kx.WithRegularField("NestedType", false),
			kx.WithJSONField("Metadata", []kx.JSONPathConfig{
				{Path: "sensitive.ssn.value", Hash: false},
				{Path: "sensitive.passport.value", Hash: false},
			}),
		)
		metadata := `{
				"sensitive": {
					"ssn": {
						"value": "123-45-6789"
					},
					"passport": {
						"value": "AB123456"
					}
				},
				"public": {
					"age": 30,
					"country": "US"
				}
			}`
		expectedEncryptedMetadata := `{"sensitive": {"ssn":{}, "passport":{}}, "public": {"age": 30, "country": "US"}}`
		original := &ComplexTestStruct{
			ID:        "123",
			Name:      "Test Name",
			CreatedAt: time.Now(),
			Numbers:   []int{1, 2, 3, 4, 5},
			NestedType: NestedType{
				Key:   "test-key",
				Value: "test-value",
			},
			Metadata: []byte(metadata),
		}

		// Test encryption
		manager := mustNewManager(t)
		encrypted, ciphertext := mustEncryptObj(t, original, manager)
		// encrypted fields should be removed
		assert.JSONEq(t, expectedEncryptedMetadata, string(encrypted.Metadata))

		// Test decryption
		decrypted := mustDecryptObj(t, encrypted, ciphertext, manager)

		assert.True(t, cmp.Equal(decrypted, original,
			// we ignore the Metadata in the comparison, and compare it with `assert.JSONEq`
			cmpopts.IgnoreFields(ComplexTestStruct{}, "ID", "Metadata")),
		)
		assert.JSONEq(t, metadata, string(decrypted.Metadata))
	})

	t.Run("encrypt_and_decrypt_nested_json_field", func(t *testing.T) {
		type TestStruct struct {
			Metadata datatypes.JSON
		}

		t.Run("snake_case_json", func(t *testing.T) {
			registry.MustRegisterStruct(TestStruct{},
				kx.WithJSONField("Metadata", []kx.JSONPathConfig{
					{Path: "customer_type", Hash: true},
					{Path: "corporate_identity.department_name", Hash: true},
				}),
			)

			snakeCaseJSON := `{
				"customer_type": 2,
				"corporate_identity": {
					"department_name": "Engineering",
					"corporate_name": "Example"
				},
				"other_field": "value"
			}`

			original := &TestStruct{
				Metadata: []byte(snakeCaseJSON),
			}

			// Test encryption
			manager := mustNewManager(t)
			encrypted, ciphertext := mustEncryptObj(t, original, manager)

			expectedEncryptedJSON := fmt.Sprintf(`{
				"hashed_customer_type": "%s",
				"corporate_identity": {
					"corporate_name": "Example",
					"hashed_department_name": "%s"
				},
				"other_field": "value"
			}`, lo.Must1(manager.HashVal(2)), lo.Must1(manager.HashVal("Engineering")))

			assert.JSONEq(t, expectedEncryptedJSON, string(encrypted.Metadata))

			// Test decryption
			decrypted := mustDecryptObj(t, encrypted, ciphertext, manager)

			// Verify original data is restored
			assert.JSONEq(t, snakeCaseJSON, string(decrypted.Metadata))
		})

		t.Run("camel_case_json", func(t *testing.T) {
			registry.MustRegisterStruct(TestStruct{},
				kx.WithJSONField("Metadata", []kx.JSONPathConfig{
					{Path: "customerType", Hash: true},
					{Path: "corporateIdentity.departmentName", Hash: true},
				}),
			)

			camelCaseJSON := `{
				"customerType": 2,
				"corporateIdentity": {
					"departmentName": "Engineering",
					"corporateName": "Example"
				},
				"otherField": "value"
			}`

			original := &TestStruct{
				Metadata: []byte(camelCaseJSON),
			}

			// Test encryption with camelCase JSON
			manager := mustNewManager(t)
			encrypted, ciphertext := mustEncryptObj(t, original, manager)

			expectedEncryptedJSON := fmt.Sprintf(`{
				"hashed_customerType": "%s",
				"corporateIdentity": {
					"hashed_departmentName": "%s",
					"corporateName": "Example"
				},
				"otherField": "value"
			}`, lo.Must1(manager.HashVal(2)),
				lo.Must1(manager.HashVal("Engineering")),
			)
			assert.JSONEq(t, expectedEncryptedJSON, string(encrypted.Metadata))

			// Test decryption
			decrypted := mustDecryptObj(t, encrypted, ciphertext, manager)

			// Verify original data is restored
			assert.JSONEq(t, camelCaseJSON, string(decrypted.Metadata))
		})
	})
}

func TestManager_Hash(t *testing.T) {
	cipherFactory := mock.NewCipherFactory()
	hashKey := getHashKey(t)
	hashFactory, err := xhmac.NewHashFactory(hashKey)
	require.NoError(t, err)
	registry, err := kx.NewRegistry()
	require.NoError(t, err)
	mustNewManager := func(t *testing.T) *kx.Manager {
		manager, err := kx.NewManager(cipherFactory, hashFactory, registry)
		require.NoError(t, err)
		return manager
	}

	t.Run("success", func(t *testing.T) {
		type User struct {
			Password       string
			HashedPassword string
		}

		registry.MustRegisterStruct(User{}, kx.WithRegularField("Password", true))
		manager := mustNewManager(t)

		original := &User{
			Password: "mypassword123",
		}

		encrypted, ciphertext := mustEncryptObj(t, original, manager)
		assert.NotEmpty(t, encrypted.HashedPassword)
		assert.Equal(t, "mypassword123", encrypted.Password)

		// Test decryption
		decrypted := mustDecryptObj(t, encrypted, ciphertext, manager)
		assert.Equal(t, encrypted.HashedPassword, decrypted.HashedPassword)
		assert.Equal(t, "mypassword123", decrypted.Password)
	})

	t.Run("missing_hashed_field", func(t *testing.T) {
		type User struct {
			Password string
			// HashedPassword field is missing
		}

		registry.MustRegisterStruct(User{}, kx.WithRegularField("Password", true))
		manager := mustNewManager(t)

		original := &User{
			Password: "mypassword123",
		}

		encrypted, ciphertext, err := manager.EncryptStruct(ctx, original, nil)
		require.Nil(t, encrypted)
		require.Empty(t, ciphertext)
		require.ErrorContains(t, err, "no corresponding HashedPassword string field found")
	})

	t.Run("wrong_hashed_field_type", func(t *testing.T) {
		type User struct {
			Password       string
			HashedPassword []byte // Wrong type, should be string
		}
		registry.MustRegisterStruct(User{}, kx.WithRegularField("Password", true))
		manager := mustNewManager(t)
		original := &User{
			Password: "mypassword123",
		}

		encrypted, ciphertext, err := manager.EncryptStruct(ctx, original, nil)
		require.Empty(t, ciphertext)
		require.Nil(t, encrypted)
		require.ErrorContains(t, err, "HashedPassword field must be string type")
	})

	t.Run("hash_json", func(t *testing.T) {
		t.Run("[] byte", func(t *testing.T) {
			type User struct {
				Password       string
				HashedPassword string
				Profile        []byte
			}
			registry.MustRegisterStruct(User{},
				kx.WithRegularField("Password", true),
				kx.WithJSONField("Profile", []kx.JSONPathConfig{
					{Path: "username", Hash: false}, // Do not hash this field
					{Path: "gender", Hash: true},    // Hash this field
				}),
			)
			manager := mustNewManager(t)
			original := &User{
				Password: "1234",
				Profile:  []byte(`{"username": "alice", "gender": "female"}`),
			}
			encrypted, ciphertext := mustEncryptObj(t, original, manager)
			assert.NotEmpty(t, encrypted.HashedPassword)

			decrypted := mustDecryptObj(t, encrypted, ciphertext, manager)
			assert.Equal(t, original.Password, decrypted.Password)
			assert.JSONEq(t, string(original.Profile), string(decrypted.Profile))
		})

		t.Run("datatypes.JSON", func(t *testing.T) {
			type User struct {
				Password       string
				HashedPassword string
				Profile        datatypes.JSON
			}
			registry.MustRegisterStruct(User{},
				kx.WithRegularField("Password", true),
				kx.WithJSONField("Profile", []kx.JSONPathConfig{
					{Path: "username", Hash: false}, // Do not hash this field
					{Path: "gender", Hash: true},    // Hash this field
				}),
			)
			manager := mustNewManager(t)
			original := &User{
				Password: "1234",
				Profile:  []byte(`{"username": "alice", "gender": "female"}`),
			}
			encrypted, ciphertext := mustEncryptObj(t, original, manager)
			assert.NotEmpty(t, encrypted.HashedPassword)

			decrypted := mustDecryptObj(t, encrypted, ciphertext, manager)
			assert.JSONEq(t, string(original.Profile), string(decrypted.Profile))
		})
	})

	t.Run("hash_consistency", func(t *testing.T) {
		type User struct {
			Password       string
			HashedPassword string
			EncryptedData  string
		}

		registry.MustRegisterStruct(User{}, kx.WithRegularField("Password", true))
		manager := mustNewManager(t)
		originalA := &User{Password: "mypassword123"}
		originalB := &User{Password: "mypassword123"}

		// Hash same password twice
		encryptedA, _ := mustEncryptObj(t, originalA, manager)
		encryptedB, _ := mustEncryptObj(t, originalB, manager)

		// Should get same hash
		assert.NotEmpty(t, encryptedA.HashedPassword)
		assert.Equal(t, encryptedA.HashedPassword, encryptedB.HashedPassword)
	})

	t.Run("embedded_hash_fields", func(t *testing.T) {
		// Define a struct to hold all hash fields
		type HashFields struct {
			HashedUsername string
			HashedEmail    string
			HashedPassword string
		}

		// User struct embeds HashFields
		type User struct {
			HashFields // Embed HashFields
			Username   string
			Email      string
			Password   string
		}

		registry.MustRegisterStruct(User{},
			kx.WithRegularField("Password", true),
			kx.WithRegularField("Username", true),
			kx.WithRegularField("Email", true))
		manager := mustNewManager(t)

		original := &User{
			Username: "john_doe",
			Email:    "john@example.com",
			Password: "secret123",
		}

		// Test encryption
		encrypted, ciphertext := mustEncryptObj(t, original, manager)

		// Verify all hash fields are set
		assert.NotEmpty(t, encrypted.HashedUsername)
		assert.NotEmpty(t, encrypted.HashedEmail)
		assert.NotEmpty(t, encrypted.HashedPassword)

		// Test decryption
		decrypted := mustDecryptObj(t, encrypted, ciphertext, manager)

		// Verify hashes remain unchanged
		assert.Equal(t, encrypted.HashedUsername, decrypted.HashedUsername)
		assert.Equal(t, encrypted.HashedEmail, decrypted.HashedEmail)
		assert.Equal(t, encrypted.HashedPassword, decrypted.HashedPassword)

		// Verify decrypted values
		assert.Equal(t, "john_doe", decrypted.Username)
		assert.Equal(t, "john@example.com", decrypted.Email)
		assert.Equal(t, "secret123", decrypted.Password)
	})
}

// TestManager_NestedStruct tests encryption/decryption of nested structs
func TestManager_NestedStruct(t *testing.T) {
	t.Run("nested_struct", func(t *testing.T) {
		type Inner struct {
			Secret string
		}
		type Outer struct {
			Name  string
			Inner Inner
		}

		registry, _ := kx.NewRegistry()
		registry.MustRegisterStruct(Inner{}, kx.WithRegularField("Secret", false))
		registry.MustRegisterStruct(Outer{})
		manager := mustNewManagerWithRegistry(t, registry)

		original := &Outer{
			Name: "test",
			Inner: Inner{
				Secret: "my-secret-value",
			},
		}

		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		assert.Equal(t, "test", encrypted.Name)
		assert.Empty(t, encrypted.Inner.Secret) // Should be cleared in encrypted object

		decrypted, err := kx.DecryptStruct(ctx, manager, encrypted, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, "test", decrypted.Name)
		assert.Equal(t, "my-secret-value", decrypted.Inner.Secret)
	})

	t.Run("nested_struct_pointer", func(t *testing.T) {
		type Inner struct {
			Secret string
		}
		type Outer struct {
			Name  string
			Inner *Inner
		}

		registry, _ := kx.NewRegistry()
		registry.MustRegisterStruct(Inner{}, kx.WithRegularField("Secret", false))
		registry.MustRegisterStruct(Outer{})
		manager := mustNewManagerWithRegistry(t, registry)

		original := &Outer{
			Name: "test",
			Inner: &Inner{
				Secret: "my-secret-value",
			},
		}

		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		assert.Equal(t, "test", encrypted.Name)
		require.NotNil(t, encrypted.Inner)
		assert.Empty(t, encrypted.Inner.Secret)

		decrypted, err := kx.DecryptStruct(ctx, manager, encrypted, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, "test", decrypted.Name)
		require.NotNil(t, decrypted.Inner)
		assert.Equal(t, "my-secret-value", decrypted.Inner.Secret)
	})

	t.Run("nested_struct_nil_pointer", func(t *testing.T) {
		type Inner struct {
			Secret string
		}
		type Outer struct {
			Name  string
			Inner *Inner
		}

		registry, _ := kx.NewRegistry()
		registry.MustRegisterStruct(Inner{}, kx.WithRegularField("Secret", false))
		registry.MustRegisterStruct(Outer{})
		manager := mustNewManagerWithRegistry(t, registry)

		original := &Outer{
			Name:  "test",
			Inner: nil,
		}

		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		assert.Equal(t, "test", encrypted.Name)
		assert.Nil(t, encrypted.Inner)
		// No encrypted fields, so ciphertext is empty - skip decryption test
		assert.Empty(t, ciphertext)
	})
}

// TestManager_SliceOfStructs tests encryption/decryption of slices containing structs
func TestManager_SliceOfStructs(t *testing.T) {
	t.Run("slice_of_structs", func(t *testing.T) {
		type Provider struct {
			ID           string
			ClientSecret string
		}
		type Config struct {
			Name      string
			Providers []Provider
		}

		registry, _ := kx.NewRegistry()
		registry.MustRegisterStruct(Provider{}, kx.WithRegularField("ClientSecret", false))
		registry.MustRegisterStruct(Config{})
		manager := mustNewManagerWithRegistry(t, registry)

		original := &Config{
			Name: "my-config",
			Providers: []Provider{
				{ID: "google", ClientSecret: "google-secret"},
				{ID: "github", ClientSecret: "github-secret"},
				{ID: "microsoft", ClientSecret: "microsoft-secret"},
			},
		}

		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		assert.Equal(t, "my-config", encrypted.Name)
		require.Len(t, encrypted.Providers, 3)
		// Verify secrets are cleared
		assert.Equal(t, "google", encrypted.Providers[0].ID)
		assert.Empty(t, encrypted.Providers[0].ClientSecret)
		assert.Equal(t, "github", encrypted.Providers[1].ID)
		assert.Empty(t, encrypted.Providers[1].ClientSecret)
		assert.Equal(t, "microsoft", encrypted.Providers[2].ID)
		assert.Empty(t, encrypted.Providers[2].ClientSecret)

		decrypted, err := kx.DecryptStruct(ctx, manager, encrypted, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, "my-config", decrypted.Name)
		require.Len(t, decrypted.Providers, 3)
		// Verify secrets are restored
		assert.Equal(t, "google", decrypted.Providers[0].ID)
		assert.Equal(t, "google-secret", decrypted.Providers[0].ClientSecret)
		assert.Equal(t, "github", decrypted.Providers[1].ID)
		assert.Equal(t, "github-secret", decrypted.Providers[1].ClientSecret)
		assert.Equal(t, "microsoft", decrypted.Providers[2].ID)
		assert.Equal(t, "microsoft-secret", decrypted.Providers[2].ClientSecret)
	})

	t.Run("slice_of_struct_pointers", func(t *testing.T) {
		type Provider struct {
			ID           string
			ClientSecret string
		}
		type Config struct {
			Name      string
			Providers []*Provider
		}

		registry, _ := kx.NewRegistry()
		registry.MustRegisterStruct(Provider{}, kx.WithRegularField("ClientSecret", false))
		registry.MustRegisterStruct(Config{})
		manager := mustNewManagerWithRegistry(t, registry)

		original := &Config{
			Name: "my-config",
			Providers: []*Provider{
				{ID: "google", ClientSecret: "google-secret"},
				{ID: "github", ClientSecret: "github-secret"},
			},
		}

		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		assert.Equal(t, "my-config", encrypted.Name)
		require.Len(t, encrypted.Providers, 2)
		assert.Empty(t, encrypted.Providers[0].ClientSecret)
		assert.Empty(t, encrypted.Providers[1].ClientSecret)

		decrypted, err := kx.DecryptStruct(ctx, manager, encrypted, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, "my-config", decrypted.Name)
		require.Len(t, decrypted.Providers, 2)
		assert.Equal(t, "google-secret", decrypted.Providers[0].ClientSecret)
		assert.Equal(t, "github-secret", decrypted.Providers[1].ClientSecret)
	})

	t.Run("empty_slice", func(t *testing.T) {
		type Provider struct {
			ID           string
			ClientSecret string
		}
		type Config struct {
			Name      string
			Providers []Provider
		}

		registry, _ := kx.NewRegistry()
		registry.MustRegisterStruct(Provider{}, kx.WithRegularField("ClientSecret", false))
		registry.MustRegisterStruct(Config{})
		manager := mustNewManagerWithRegistry(t, registry)

		original := &Config{
			Name:      "my-config",
			Providers: []Provider{},
		}

		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		assert.Equal(t, "my-config", encrypted.Name)
		assert.Empty(t, encrypted.Providers)
		// No encrypted fields (empty slice), so ciphertext is empty - skip decryption test
		assert.Empty(t, ciphertext)
	})

	t.Run("multiple_sensitive_fields", func(t *testing.T) {
		type Provider struct {
			ID           string
			ClientSecret string
			PrivateKey   string
		}
		type Config struct {
			Name      string
			Providers []Provider
		}

		registry, _ := kx.NewRegistry()
		registry.MustRegisterStruct(Provider{},
			kx.WithRegularField("ClientSecret", false),
			kx.WithRegularField("PrivateKey", false),
		)
		registry.MustRegisterStruct(Config{})
		manager := mustNewManagerWithRegistry(t, registry)

		original := &Config{
			Name: "my-config",
			Providers: []Provider{
				{ID: "apple", ClientSecret: "apple-secret", PrivateKey: "apple-key"},
				{ID: "google", ClientSecret: "google-secret", PrivateKey: ""},
			},
		}

		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		assert.Empty(t, encrypted.Providers[0].ClientSecret)
		assert.Empty(t, encrypted.Providers[0].PrivateKey)
		assert.Empty(t, encrypted.Providers[1].ClientSecret)
		assert.Empty(t, encrypted.Providers[1].PrivateKey)

		decrypted, err := kx.DecryptStruct(ctx, manager, encrypted, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, "apple-secret", decrypted.Providers[0].ClientSecret)
		assert.Equal(t, "apple-key", decrypted.Providers[0].PrivateKey)
		assert.Equal(t, "google-secret", decrypted.Providers[1].ClientSecret)
		assert.Equal(t, "", decrypted.Providers[1].PrivateKey)
	})
}

// TestManager_UnregisteredNestedStruct tests that unregistered nested structs are skipped
func TestManager_UnregisteredNestedStruct(t *testing.T) {
	t.Run("unregistered_nested_struct_skipped", func(t *testing.T) {
		type Inner struct {
			Secret string
		}
		type Outer struct {
			Name  string
			Inner Inner
		}

		registry, _ := kx.NewRegistry()
		// Only register Outer, not Inner
		registry.MustRegisterStruct(Outer{})
		manager := mustNewManagerWithRegistry(t, registry)

		original := &Outer{
			Name: "test",
			Inner: Inner{
				Secret: "my-secret-value",
			},
		}

		encrypted, ciphertext, err := kx.EncryptStruct(ctx, manager, original, nil)
		require.NoError(t, err)
		assert.Equal(t, "test", encrypted.Name)
		// Inner.Secret should NOT be encrypted since Inner is not registered
		assert.Equal(t, "my-secret-value", encrypted.Inner.Secret)
		// No encrypted fields, so ciphertext is empty
		assert.Empty(t, ciphertext)
	})
}

func mustNewManagerWithRegistry(t *testing.T, registry *kx.Registry) *kx.Manager {
	cipherFactory := mock.NewCipherFactory()
	hashKey := getHashKey(t)
	hashFactory, err := xhmac.NewHashFactory(hashKey)
	require.NoError(t, err)
	manager, err := kx.NewManager(cipherFactory, hashFactory, registry)
	require.NoError(t, err)
	return manager
}
