package pingsocket

import (
	"net"
	"time"
)

type Pingsocket interface {
	SetTTL(ttl uint8) error
	Close() error
	SetReadTimeout(duration time.Duration) error
	SendTo(packet []byte, destination net.IP) error
	Recvfrom(buf []byte) (n int, from net.IP, err error)
}

func SocketForAddress(address net.IP) (Pingsocket, error) {
	if address.To4() == nil {
		return NewIPv6()
	}
	return NewIPv4()
}
