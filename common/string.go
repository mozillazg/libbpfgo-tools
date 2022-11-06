package common

import "bytes"

func GoString(v []byte) string {
	return string(bytes.TrimRight(v, "\x00"))
}
