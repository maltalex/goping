package pingsocket

import (
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"time"
)

const (
	TIMEOUTERR = windows.WSAETIMEDOUT
)

var (
	ErrNotIPV4 = errors.New("the given address is not IPv4")
)

type IPv4 struct {
	socket windows.Handle
}

func NewIPv4() (s IPv4, err error) {
	fd, e := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_ICMP)
	return IPv4{socket: fd}, e
}

func (s IPv4) SetTTL(ttl uint8) error {
	return windows.SetsockoptInt(s.socket, windows.IPPROTO_IP, windows.IP_TTL, int(ttl))
}

func (s IPv4) SetReadTimeout(duration time.Duration) error {
	//TODO check sanity of incoming value
	return windows.SetsockoptInt(s.socket, windows.SOL_SOCKET, windows.SO_RCVTIMEO, int(duration.Milliseconds()))
}

func (s IPv4) SendTo(packet []byte, destination net.IP) error {
	if destination.To4() == nil {
		return ErrNotIPV4
	}
	var dest windows.SockaddrInet4
	for i := 0; i < 4; i++ {
		dest.Addr[i] = destination[len(destination)-4+i]
	}
	return windows.Sendto(s.socket, packet, 0, &dest)
}

func (s IPv4) Recvfrom(buf []byte) (n int, from [4]byte, err error) {
	n, sourceSock, e := windows.Recvfrom(s.socket, buf, 0)
	if source, ok := sourceSock.(*windows.SockaddrInet4); ok {
		return n, source.Addr, e
	}
	return n, from, e
}
