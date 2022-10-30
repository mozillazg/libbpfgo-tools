package common

import (
	"encoding/binary"
	"net"
	"net/netip"
	"unsafe"
)

const (
	AF_INET  = 2
	AF_INET6 = 10
)

type Uint128 [16]byte

func Uint32ToIpV4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func Ntohs(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

func AddrFrom16(family uint16, addr [16]byte) netip.Addr {
	switch family {
	case AF_INET:
		v := [4]byte{}
		for i := 0; i < 4; i++ {
			v[i] = addr[i]
		}
		return netip.AddrFrom4(v)
	default:
		return netip.AddrFrom16(addr)
	}
}
