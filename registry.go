package protection

import (
	"reflect"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

type Registry struct {
	structConfigs map[reflect.Type]*StructConfig
}

type RegistryOption func(*Registry)

// NewRegistry creates a new encryption configuration with the provided options
func NewRegistry(opts ...RegistryOption) (*Registry, error) {
	registry := &Registry{
		structConfigs: make(map[reflect.Type]*StructConfig),
	}

	for _, opt := range opts {
		opt(registry)
	}

	// Currently, `NewRegistry` does not return an error.
	// However, to ensure that clients won't need to modify their code
	// in the future if error handling becomes necessary,
	// the function signature is designed to include an `error` return value.
	return registry, nil
}

// StructConfig represents the configuration for a struct type
type StructConfig struct {
	// RegularFields maps field names to whether they should be hashed
	// If a field exists in this map, it will be encrypted
	// The bool value indicates whether it should also be hashed
	RegularFields map[string]bool
	// JSONFields maps field names to their JSON path configuration
	JSONFields map[string]*JSONFieldConfig
}

// JSONPathConfig represents the configuration for a single JSON path
type JSONPathConfig struct {
	Path string `confx:"path"`
	Hash bool   `confx:"hash"`
}

// JSONFieldConfig represents the configuration for a JSON field
type JSONFieldConfig struct {
	EncryptPaths []string
	HashPaths    []string
}

// StructOption represents a configuration option for a struct
type StructOption func(*StructConfig)

// WithRegularField adds a plain field configuration
func WithRegularField(name string, hash bool) StructOption {
	return func(c *StructConfig) {
		c.RegularFields[name] = hash
	}
}

// WithJSONField adds a JSON field configuration
func WithJSONField(name string, paths []JSONPathConfig) StructOption {
	return func(c *StructConfig) {
		config := &JSONFieldConfig{
			EncryptPaths: make([]string, 0, len(paths)),
			HashPaths:    make([]string, 0, len(paths)),
		}
		for _, p := range paths {
			config.EncryptPaths = append(config.EncryptPaths, p.Path)
			if p.Hash {
				config.HashPaths = append(config.HashPaths, p.Path)
			}
		}
		c.JSONFields[name] = config
	}
}

// validateJSONPath checks if a JSON path is valid (no wildcards or array indices)
func validateJSONPath(path string) error {
	splits := strings.Split(path, ".")
	for _, part := range splits {
		if strings.Contains(path, "*") {
			return errors.Errorf("wildcards are not supported in JSON paths, got %s", path)
		}
		if len(part) == 1 {
			if unicode.IsDigit(rune(part[0])) {
				return errors.Errorf("array indices are not supported in JSON paths, got %s", path)
			}
			if part[0] == '#' {
				return errors.New("# is not supported in JSON paths")
			}
		}
	}
	return nil
}

// RegisterStruct adds a struct type to be encrypted with the given options
func (r *Registry) RegisterStruct(obj any, opts ...StructOption) error {
	typ := GetObjType(obj)
	if typ.Kind() != reflect.Struct {
		return errors.Errorf("value must be a struct or pointer to struct")
	}

	config := &StructConfig{
		RegularFields: make(map[string]bool),
		JSONFields:    make(map[string]*JSONFieldConfig),
	}

	// Apply all options
	for _, opt := range opts {
		opt(config)
	}

	// Validate all configured fields
	for fieldName := range config.RegularFields {
		if _, ok := typ.FieldByName(fieldName); !ok {
			return errors.Errorf("field %s not found in struct %v", fieldName, typ)
		}
	}

	for fieldName := range config.JSONFields {
		field, ok := typ.FieldByName(fieldName)
		if !ok {
			return errors.Errorf("field %s not found in struct %v", fieldName, typ)
		}
		// JSON fields must be []byte or its alias types
		if field.Type.Kind() != reflect.Slice || field.Type.Elem().Kind() != reflect.Uint8 {
			return errors.Errorf("JSON field %s must be []byte or its alias types, got %v", fieldName, field.Type)
		}
	}

	r.structConfigs[typ] = config
	return nil
}

func (r *Registry) MustRegisterStruct(v any, opts ...StructOption) {
	if err := r.RegisterStruct(v, opts...); err != nil {
		panic(err)
	}
}

// GetStructConfig retrieves the configuration for a struct type
// Returns nil if no configuration exists for the type
func (r *Registry) GetStructConfig(obj any) *StructConfig {
	return r.structConfigs[GetObjType(obj)]
}

func GetRegularHashedFieldName(fieldName string) string {
	// should we support client to specify hashed field prefix?
	return "Hashed" + fieldName
}

func GetJSONHashedFieldName(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "hashed_" + path
	}
	if len(parts) == 1 {
		return "hashed_" + path
	}
	lastPart := parts[len(parts)-1]
	prefix := strings.Join(parts[:len(parts)-1], ".")
	return prefix + ".hashed_" + lastPart
}
