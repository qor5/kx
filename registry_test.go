package kx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateJSONPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"Valid path", "user.name.first", false},
		{"Path with wildcard", "user.*.name", true},
		{"Path with array index", "users.0.name", true},
		{"Path with #", "user.#.name", true},
		{"Empty path", "", false},
		{"Single letter path", "a", false},
		{"Path with multiple dots", "this.is.a.long.path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJSONPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateJSONPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestRegistry_RegisterStruct(t *testing.T) {
	type User struct {
		Password       string
		HashedPassword string
		Profile        []byte
		Settings       string
		Tags           []string
	}

	tests := []struct {
		name         string
		structType   any
		structOpts   []StructOption
		registryOpts []RegistryOption
		errContains  string
	}{
		{
			name:       "valid fields",
			structType: User{},
			structOpts: []StructOption{
				WithRegularField("Password", true),
				WithJSONField("Profile", []JSONPathConfig{{Path: "secret", Hash: true}}),
			},
		},
		{
			name:       "non-existent field",
			structType: User{},
			structOpts: []StructOption{
				WithRegularField("NonExistent", true),
			},
			errContains: "field NonExistent not found",
		},
		{
			name:       "wrong JSON field type - string",
			structType: User{},
			structOpts: []StructOption{
				WithJSONField("Settings", []JSONPathConfig{{Path: "theme", Hash: true}}),
			},
			errContains: "must be []byte",
		},
		{
			name:       "wrong JSON field type - []string",
			structType: User{},
			structOpts: []StructOption{
				WithJSONField("Tags", []JSONPathConfig{{Path: "0", Hash: true}}),
			},
			errContains: "must be []byte",
		},
		{
			name:        "non-struct type",
			structType:  "not a struct",
			structOpts:  []StructOption{},
			errContains: "must be a struct",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, err := NewRegistry()
			require.NoError(t, err)
			err = registry.RegisterStruct(tt.structType, tt.structOpts...)

			if tt.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetJSONHashedFieldName(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple path",
			path:     "field",
			expected: "hashed_field",
		},
		{
			name:     "nested path",
			path:     "parent.child",
			expected: "parent.hashed_child",
		},
		{
			name:     "deeply nested path",
			path:     "grandparent.parent.child",
			expected: "grandparent.parent.hashed_child",
		},
		{
			name:     "snake case path",
			path:     "user_info.first_name",
			expected: "user_info.hashed_first_name",
		},
		{
			name:     "camel case path",
			path:     "userInfo.firstName",
			expected: "userInfo.hashed_firstName",
		},
		{
			name:     "mixed case path",
			path:     "user_info.firstName",
			expected: "user_info.hashed_firstName",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "hashed_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetJSONHashedFieldName(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
