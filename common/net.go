package common

import (
	"encoding/binary"
	"net/netip"
)

const (
	AF_INET  = 2
	AF_INET6 = 10

	SOCK_STREAM = 1
	SOCK_DGRAM  = 2
)

type Uint128 [16]byte

func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
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

func InetAton(ip string) (uint32, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return 0, err
	}
	return addrToN(addr), nil
}

func InetNtoa(ip uint32) string {
	data := [4]byte{}
	binary.LittleEndian.PutUint32(data[:], ip)
	addr := netip.AddrFrom4(data)
	return addr.String()
}

func addrToN(addr netip.Addr) uint32 {
	data := addr.As4()
	return binary.LittleEndian.Uint32(data[:])
}
