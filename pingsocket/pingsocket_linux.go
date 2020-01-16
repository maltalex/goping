package pingsocket

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"time"
)

const (
	TIMEOUTERR = unix.EWOULDBLOCK
)

var (
	ErrNotIPV4 = errors.New("the given address is not IPv4")
	ErrNotIPV6 = errors.New("the given address is not IPv6")
)

type IPv4 struct {
	socket int
}

type IPv6 struct {
	socket int
}

func NewIPv4() (s IPv4, err error) {
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	return IPv4{socket: fd}, e
}

func (s IPv4) SetTTL(ttl uint8) error {
	return unix.SetsockoptInt(s.socket, unix.IPPROTO_IP, unix.IP_TTL, int(ttl))
}

func (s IPv4) SetReadTimeout(duration time.Duration) error {
	return unix.SetsockoptTimeval(s.socket, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: int64(duration.Seconds())})
}

func (s IPv4) SendTo(packet []byte, destination net.IP) error {
	if destination.To4() == nil {
		return ErrNotIPV4
	}
	var dest unix.SockaddrInet4
	for i := 0; i < 4; i++ {
		dest.Addr[i] = destination[len(destination)-4+i]
	}
	return unix.Sendto(s.socket, packet, 0, &dest)
}

func (s IPv4) Recvfrom(buf []byte) (n int, from net.IP, err error) {
	n, sourceSock, e := unix.Recvfrom(s.socket, buf, 0)
	if source, ok := sourceSock.(*unix.SockaddrInet4); ok {
		return n, net.IPv4(source.Addr[0], source.Addr[1], source.Addr[2], source.Addr[3]), e
	}
	return n, from, e
}

func (s IPv4) Close() error {
	return unix.Close(s.socket)
}

func NewIPv6() (s IPv6, err error) {
	fd, e := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	return IPv6{socket: fd}, e
}

func (s IPv6) SetTTL(ttl uint8) error {
	return unix.SetsockoptInt(s.socket, unix.IPPROTO_IPV6, unix.IP_TTL, int(ttl))
}

func (s IPv6) SetReadTimeout(duration time.Duration) error {
	return unix.SetsockoptTimeval(s.socket, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: int64(duration.Seconds())})
}

func (s IPv6) SendTo(packet []byte, destination net.IP) error {
	if destination.To4() != nil {
		return ErrNotIPV6
	}
	var dest unix.SockaddrInet6
	for i := 0; i < 16; i++ {
		dest.Addr[i] = destination[i]
	}
	return unix.Sendto(s.socket, packet, 0, &dest)
}

func (s IPv6) Recvfrom(buf []byte) (n int, from net.IP, err error) {
	n, sourceSock, e := unix.Recvfrom(s.socket, buf, 0)
	if source, ok := sourceSock.(*unix.SockaddrInet6); ok {
		return n, source.Addr[:], e
	}
	return n, from, e
}

func (s IPv6) Close() error {
	return unix.Close(s.socket)
}
