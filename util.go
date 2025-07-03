package protection

import (
	"encoding/base64"
	"reflect"

	"github.com/pkg/errors"
)

func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func DecodeKey(key string) ([]byte, error) {
	bs, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64 key")
	}
	return bs, nil
}

func GetObjType(obj any) reflect.Type {
	return reflect.Indirect(reflect.ValueOf(obj)).Type()
}
