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
	ErrNotIPV6 = errors.New("the given address is not IPv6")
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

func (s IPv4) Recvfrom(buf []byte) (n int, from net.IP, err error) {
	n, sourceSock, e := windows.Recvfrom(s.socket, buf, 0)
	if source, ok := sourceSock.(*windows.SockaddrInet4); ok {
		return n, source.Addr[:], e
	}
	return n, from, e
}

func (s IPv4) Close() error {
	return windows.Close(s.socket)
}

type IPv6 struct {
	socket windows.Handle
}

func NewIPv6() (s IPv6, err error) {
	fd, e := windows.Socket(windows.AF_INET6, windows.SOCK_RAW, windows.IPPROTO_ICMPV6)
	return IPv6{socket: fd}, e
}

func (s IPv6) SetTTL(ttl uint8) error {
	return windows.SetsockoptInt(s.socket, windows.IPPROTO_IPV6, windows.IP_TTL, int(ttl))
}

func (s IPv6) SetReadTimeout(duration time.Duration) error {
	return windows.SetsockoptInt(s.socket, windows.SOL_SOCKET, windows.SO_RCVTIMEO, int(duration.Milliseconds()))
}

func (s IPv6) SendTo(packet []byte, destination net.IP) error {
	if destination.To4() != nil {
		return ErrNotIPV6
	}
	var dest windows.SockaddrInet6
	for i := 0; i < 16; i++ {
		dest.Addr[i] = destination[i]
	}
	return windows.Sendto(s.socket, packet, 0, &dest)
}

func (s IPv6) Recvfrom(buf []byte) (n int, from net.IP, err error) {
	n, sourceSock, e := windows.Recvfrom(s.socket, buf, 0)
	if source, ok := sourceSock.(*windows.SockaddrInet6); ok {
		return n, source.Addr[:], e
	}
	return n, from, e
}

func (s IPv6) Close() error {
	return windows.Close(s.socket)
}
