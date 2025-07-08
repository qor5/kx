package kx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	clone "github.com/huandu/go-clone/generic"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"github.com/theplant/appkit/logtracing"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/qor5/kx/api"
)

// Manager handles the encryption and decryption of structs
type Manager struct {
	cipherFactory api.CipherFactory
	hashFactory   api.HashFactory
	registry      *Registry
}

// NewManager creates a new encryption manager
func NewManager(cipherFactory api.CipherFactory, hashFactory api.HashFactory, registry *Registry, opts ...ManagerOption) (*Manager, error) {
	if registry == nil {
		return nil, errors.New("registry is required")
	}
	if cipherFactory == nil {
		return nil, errors.New("cipher factory is required")
	}
	if hashFactory == nil {
		return nil, errors.New("hash factory is required")
	}

	m := &Manager{
		registry:      registry,
		cipherFactory: cipherFactory,
		hashFactory:   hashFactory,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m, nil
}

func NewManagerByConfig(config Config, registry *Registry, opts ...ManagerOption) (*Manager, error) {
	cipherFactory, err := NewCipherFactory(config.CipherConfig)
	if err != nil {
		return nil, err
	}

	hashFactory, err := NewHashFactory(config.HasherConfig)
	if err != nil {
		return nil, err
	}
	return NewManager(cipherFactory, hashFactory, registry, opts...)
}

// RegisterStruct registers a struct type for encryption
func (m *Manager) RegisterStruct(v any, opts ...StructOption) error {
	return m.registry.RegisterStruct(v, opts...)
}

// EncryptedData represents the encrypted fields and their values
type EncryptedData struct {
	RegularFields map[string]any             // Regular field values
	JSONFields    map[string]json.RawMessage // JSON field values at specific paths
}

func (m *Manager) GetHashFactory() api.HashFactory {
	return m.hashFactory
}

func (m *Manager) GetCipherFactory() api.CipherFactory {
	return m.cipherFactory
}

func (m *Manager) GetRegistry() *Registry {
	return m.registry
}

// processStruct handles the encryption/decryption of a single field
func (m *Manager) processStruct(ps *parsedStruct, encData *EncryptedData, isEncrypt bool) error {
	// regular fields
	for fieldName, shouldHash := range ps.Config.RegularFields {
		fieldValue := ps.Value.FieldByName(fieldName)
		if isEncrypt {
			encData.RegularFields[fieldName] = fieldValue.Interface()
			if shouldHash {
				if err := m.hashRegularField(fieldName, fieldValue, ps.Value); err != nil {
					return err
				}
			}
		} else {
			if err := m.decryptRegularField(fieldName, fieldValue, encData); err != nil {
				return err
			}
		}
	}

	// json fields
	for fieldName, jsonConfig := range ps.Config.JSONFields {
		fieldValue := ps.Value.FieldByName(fieldName)
		if isEncrypt {
			if len(jsonConfig.HashPaths) > 0 {
				if err := m.hashJSONField(fieldName, fieldValue, jsonConfig.HashPaths); err != nil {
					return err
				}
			}
			if err := m.encryptJSONField(fieldName, fieldValue, encData, jsonConfig.EncryptPaths); err != nil {
				return err
			}
		} else {
			if len(jsonConfig.HashPaths) > 0 {
				if err := m.removeFieldFromJSON(fieldName, fieldValue, jsonConfig.HashPaths); err != nil {
					return err
				}
			}
			if err := m.decryptJSONField(fieldName, fieldValue, encData); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) HashVal(val any) (string, error) {
	return HashVal(m.hashFactory, val)
}

func (m *Manager) hashRegularField(fieldName string, fieldValue, parentValue reflect.Value) error {
	// Find the corresponding Hashed field
	hashedFieldName := GetRegularHashedFieldName(fieldName)
	hashedFieldValue := parentValue.FieldByName(hashedFieldName)
	if !hashedFieldValue.IsValid() {
		return errors.Errorf("hash tag used but no corresponding %s string field found", hashedFieldName)
	}
	if !hashedFieldValue.CanSet() {
		return errors.Errorf("cannot set %s field", hashedFieldName)
	}
	if hashedFieldValue.Kind() != reflect.String {
		return errors.Errorf("%s field must be string type", hashedFieldName)
	}
	hashedValue, err := m.HashVal(fieldValue.Interface())
	if err != nil {
		return err
	}
	hashedFieldValue.SetString(hashedValue)
	return nil
}

func (m *Manager) validateJSONBytes(fieldName string, jsonBytes []byte) error {
	if !gjson.ValidBytes(jsonBytes) {
		return errors.Errorf("invalid JSON data in field %s", fieldName)
	}
	return nil
}

// hashJSONField hashes the specified JSON paths in a field
func (m *Manager) hashJSONField(fieldName string, fieldValue reflect.Value, paths []string) error {
	if len(paths) == 0 {
		return nil
	}

	jsonBytes := fieldValue.Bytes()
	if err := m.validateJSONBytes(fieldName, jsonBytes); err != nil {
		return err
	}

	// For each path that needs to be hashed
	for _, path := range paths {
		// Get the value at the path
		value := gjson.GetBytes(jsonBytes, path)
		if !value.Exists() {
			continue // Skip if path doesn't exist
		}

		// Hash the value
		hashedValue, err := m.HashVal(value.String())
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to hash value at path %s", path))
		}

		jsonBytes, err = sjson.SetBytes(jsonBytes, GetJSONHashedFieldName(path), hashedValue)
		if err != nil {
			return errors.Wrapf(err, "failed to set hashed value for JSON path %s in field %s", path, fieldName)
		}
	}

	fieldValue.SetBytes(jsonBytes)
	return nil
}

// hashJSONField removed the specified JSON paths in a field
func (m *Manager) removeFieldFromJSON(fieldName string, fieldValue reflect.Value, paths []string) error {
	if len(paths) == 0 {
		return nil
	}

	jsonBytes := fieldValue.Bytes()
	if err := m.validateJSONBytes(fieldName, jsonBytes); err != nil {
		return err
	}

	// For each path that needs to be hashed
	for _, path := range paths {
		var err error
		jsonBytes, err = sjson.DeleteBytes(jsonBytes, GetJSONHashedFieldName(path))
		if err != nil {
			return errors.Wrapf(err, "failed to set hashed value for JSON path %s in field %s", path, fieldName)
		}
	}

	fieldValue.SetBytes(jsonBytes)
	return nil
}

// decryptRegularField decrypts an entirely encrypted field
func (m *Manager) decryptRegularField(fieldName string, fieldValue reflect.Value, encData *EncryptedData) error {
	encryptedValue, ok := encData.RegularFields[fieldName]
	if !ok {
		return nil // field not found in encrypted data, skip
	}

	// Try direct assignment first
	encryptedValueReflect := reflect.ValueOf(encryptedValue)
	if encryptedValueReflect.Type().AssignableTo(fieldValue.Type()) {
		fieldValue.Set(encryptedValueReflect)
		return nil
	}

	// For complex types, try JSON unmarshaling
	jsonData, err := json.Marshal(encryptedValue)
	if err != nil {
		return errors.Errorf("failed to marshal field %s: %v", fieldName, err)
	}

	newValue := reflect.New(fieldValue.Type())
	if err := json.Unmarshal(jsonData, newValue.Interface()); err != nil {
		return errors.Errorf("failed to unmarshal field %s: %v", fieldName, err)
	}

	fieldValue.Set(newValue.Elem())
	return nil
}

// encryptJSONField encrypts specific paths within a JSON field
func (m *Manager) encryptJSONField(fieldName string, fieldValue reflect.Value, encData *EncryptedData, paths []string) (err error) {
	if len(paths) == 0 {
		return nil
	}
	jsonBytes := fieldValue.Bytes()
	if err := m.validateJSONBytes(fieldName, jsonBytes); err != nil {
		return err
	}
	for _, path := range paths {
		if result := gjson.GetBytes(jsonBytes, path); result.Exists() {
			encData.JSONFields[fieldName+"."+path] = json.RawMessage(result.Raw)
			jsonBytes, err = sjson.DeleteBytes(jsonBytes, path)
			if err != nil {
				return errors.Wrapf(err, "failed to delete JSON value at path %s", path)
			}
		}
	}
	fieldValue.SetBytes(jsonBytes)
	return nil
}

// decryptJSONField decrypt encrypted paths within a JSON field
func (m *Manager) decryptJSONField(fieldName string, fieldValue reflect.Value, encData *EncryptedData) error {
	jsonBytes := fieldValue.Bytes()
	if !gjson.ValidBytes(jsonBytes) {
		jsonBytes = []byte("{}")
	}

	prefix := fieldName + "."
	for path, value := range encData.JSONFields {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		jsonPath := strings.TrimPrefix(path, prefix)
		var err error
		jsonBytes, err = sjson.SetBytes(jsonBytes, jsonPath, value)
		if err != nil {
			return errors.Wrapf(err, "failed to set JSON value at path %s", path)
		}
	}

	fieldValue.SetBytes(jsonBytes)
	return nil
}

// parsedStruct holds the parsed struct information
type parsedStruct struct {
	Value      reflect.Value
	PtrToValue reflect.Value
	Type       reflect.Type
	Config     *StructConfig
}

func (m *Manager) parse(obj any) (*parsedStruct, error) {
	val := reflect.ValueOf(obj)
	if val.Kind() != reflect.Ptr {
		return nil, errors.New(fmt.Sprintf("value must be a pointer to struct, got %T", obj))
	}
	if val.Elem().Kind() != reflect.Struct {
		return nil, errors.New(fmt.Sprintf("value must be a pointer to struct, got %T", obj))
	}

	config := m.registry.GetStructConfig(obj)
	if config == nil {
		return nil, errors.Errorf("no encryption configuration found for type %T", obj)
	}

	clonedObj := clone.Clone(obj)
	val = reflect.ValueOf(clonedObj)
	return &parsedStruct{
		Value:      reflect.Indirect(val),
		PtrToValue: val,
		Config:     config,
	}, nil
}

// EncryptStruct encrypts the fields in a struct based on configuration
func (m *Manager) EncryptStruct(ctx context.Context, obj any, encryptionContext map[string]string) (encryptedObj any, ciphertext string, err error) {
	return EncryptStruct(ctx, m, obj, encryptionContext)
}

// DecryptStruct decrypts the fields in a struct based on configuration
func (m *Manager) DecryptStruct(ctx context.Context, encryptedObj any, ciphertext string, encryptionContext map[string]string) (decryptedObj any, err error) {
	return DecryptStruct(ctx, m, encryptedObj, ciphertext, encryptionContext)
}

func EncryptStruct[T any](ctx context.Context, m *Manager, obj T, encryptionContext map[string]string) (encryptedObj T, ciphertext string, err error) {
	ctx, _ = logtracing.StartSpan(ctx, "protection/EncryptStruct")
	defer func() {
		logtracing.EndSpan(ctx, err)
	}()
	defer logtracing.RecordPanic(ctx)
	ps, err := m.parse(obj)
	var zeroValue T
	if err != nil {
		return zeroValue, "", err
	}

	// Collect data to be encrypted
	encData := &EncryptedData{
		RegularFields: make(map[string]any),
		JSONFields:    make(map[string]json.RawMessage),
	}

	if err := m.processStruct(ps, encData, true); err != nil {
		return zeroValue, "", err
	}

	ciphertext, err = EncryptData(ctx, m, encData, encryptionContext)
	if err != nil {
		return zeroValue, "", err
	}

	return ps.PtrToValue.Interface().(T), ciphertext, nil
}

func EncryptData(ctx context.Context, m *Manager, encData *EncryptedData, encryptionContext map[string]string) (ciphertext string, err error) {
	if len(encData.RegularFields) == 0 && len(encData.JSONFields) == 0 {
		// if no data to encrypt, nothing to do
		return "", nil
	}

	// Serialize and encrypt the entire EncryptedData
	plaintext, err := json.Marshal(encData)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal encrypted data")
	}

	// Create encrypter and encrypt
	encrypter := m.cipherFactory.NewEncrypter()
	cipherBytes, err := encrypter.Encrypt(ctx, plaintext, encryptionContext)
	if err != nil {
		return "", errors.Wrap(err, "failed to encrypt data")
	}
	ciphertext = base64.StdEncoding.EncodeToString(cipherBytes)
	return ciphertext, nil
}

func DecryptCiphertext(ctx context.Context, m *Manager, ciphertext string, encryptionContext map[string]string) (*EncryptedData, error) {
	// Decode base64
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64")
	}

	// Create decrypter and decrypt
	decrypter := m.cipherFactory.NewDecrypter()
	plaintext, err := decrypter.Decrypt(ctx, ciphertextBytes, encryptionContext)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data")
	}

	// Unmarshal encrypted data
	var encData EncryptedData
	if err := json.Unmarshal(plaintext, &encData); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal encrypted data")
	}
	return &encData, nil
}

func DecryptStruct[T any](ctx context.Context, m *Manager, encryptedObj T, ciphertext string, encryptionContext map[string]string) (result T, err error) {
	ctx, _ = logtracing.StartSpan(ctx, "protection/DecryptStruct")
	defer func() {
		logtracing.EndSpan(ctx, err)
	}()
	defer logtracing.RecordPanic(ctx)
	var zeroValue T
	if ciphertext == "" {
		return zeroValue, errors.New("ciphertext is required")
	}
	ps, err := m.parse(encryptedObj)
	if err != nil {
		return zeroValue, err
	}

	encData, err := DecryptCiphertext(ctx, m, ciphertext, encryptionContext)
	if err != nil {
		return zeroValue, err
	}

	if err := m.processStruct(ps, encData, false); err != nil {
		return zeroValue, err
	}

	return ps.PtrToValue.Interface().(T), nil
}

// ValidateEncryptedJSON validates if the given encrypted JSON bytes conform to the expected structure
func ValidateEncryptedJSON(encryptedJSON []byte, config *JSONFieldConfig) error {
	if !gjson.ValidBytes(encryptedJSON) {
		return errors.New("invalid JSON data")
	}

	// Check all paths that should be empty in encrypted JSON
	for _, path := range config.EncryptPaths {
		value := gjson.GetBytes(encryptedJSON, path)
		if value.Exists() {
			return errors.Errorf("path %q should be empty in encrypted JSON", path)
		}
	}

	// Check all paths that should have hashed values
	for _, path := range config.HashPaths {
		// Original field should be empty
		value := gjson.GetBytes(encryptedJSON, path)
		if value.Exists() {
			return errors.Errorf("path %q should be empty in encrypted JSON", path)
		}

		// Hashed field should exist and not be empty
		hashedPath := GetJSONHashedFieldName(path)
		hashedValue := gjson.GetBytes(encryptedJSON, hashedPath)
		if !hashedValue.Exists() {
			return errors.Errorf("hashed path %q not found in encrypted JSON", hashedPath)
		}
		// TODO: if input is empty, is hashed value empty?
		if hashedValue.String() == "" {
			return errors.Errorf("hashed path %q should not be empty in encrypted JSON", hashedPath)
		}
	}

	return nil
}
