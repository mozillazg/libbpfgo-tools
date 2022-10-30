package common

import (
	"net/netip"
)

const (
	AF_INET  = 2
	AF_INET6 = 10
)

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
