package common

import "bytes"

func GoString(v []byte) string {
	return string(bytes.TrimRight(v, "\x00"))
}

func GoPath(v []byte) string {
	return GoString(bytes.Split(v, []byte("\x00"))[0])
}
