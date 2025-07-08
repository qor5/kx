package kx

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/text/width"

	"github.com/qor5/kx/api"
)

// HashVal hashes a value using the provided hash factory.
// For string values:
//   - Converts to lowercase for case-insensitive comparison
//   - Uses width.Narrow to convert full-width characters to their half-width equivalents
//     This ensures that characters like "Ｈｅｌｌｏ" and "Hello" produce the same hash.
//     See https://unicode.org/reports/tr11/ for more details about East Asian Width.
//
// For []byte values:
//   - Uses the bytes directly without any transformation
//
// For other types:
//   - Marshals to JSON before hashing
func HashVal(hashFactory api.HashFactory, val any) (string, error) {
	rv := reflect.Indirect(reflect.ValueOf(val))
	var data []byte
	switch rv.Kind() {
	case reflect.String:
		data = []byte(strings.ToLower(width.Narrow.String(rv.String())))
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			data = rv.Bytes()
			break
		}
		// if kind is slice but its element type is not uint8, fall through.
		fallthrough
	default:
		jsonData, err := json.Marshal(rv.Interface())
		if err != nil {
			return "", errors.Wrap(err, "failed to marshal value for hashing")
		}
		data = jsonData
	}
	h := hashFactory.NewHash()
	_, err := h.Write(data)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash value")
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
