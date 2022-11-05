package common

import (
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

func DumpHash(bpfMap *bpf.BPFMap) ([][2][]byte, error) {
	var ret [][2][]byte
	iter := bpfMap.Iterator()
	for iter.Next() {
		key := iter.Key()
		value, err := bpfMap.GetValue(unsafe.Pointer(&key[0]))
		if err != nil {
			return nil, err
		}
		ret = append(ret, [2][]byte{key, value})
	}
	return ret, nil
}

func DumpThenClearHash(bpfMap *bpf.BPFMap) ([][2][]byte, error) {
	ret, err := DumpHash(bpfMap)
	if err != nil {
		return ret, nil
	}
	return ret, clearHash(bpfMap)
}

func clearHash(bpfMap *bpf.BPFMap) error {
	iter := bpfMap.Iterator()
	for iter.Next() {
		key := iter.Key()
		if err := bpfMap.DeleteKey(unsafe.Pointer(&key[0])); err != nil {
			return err
		}
	}
	return nil
}
