package main

import (
	"syscall"
	"unsafe"
)

const (
	InvalidHandle         = ^Handle(0)
	errnoERROR_IO_PENDING = 997
	AF_INET               = 2
	SOCK_RAW              = 3
	IPPROTO_ICMP          = 1
)

var (
	modws2_32, _              = syscall.LoadLibrary("ws2_32.dll")
	procsendto, _             = syscall.GetProcAddress(modws2_32, "sendto")
	procrecvfrom, _           = syscall.GetProcAddress(modws2_32, "recvfrom")
	procsocket, _             = syscall.GetProcAddress(modws2_32, "socket")
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

type Handle uintptr
type Sockaddr interface {
	sockaddr() (ptr unsafe.Pointer, len int32, err error) // lowercase; only we can define Sockaddrs
}

type SockaddrInet4 struct {
	Port int
	Addr [4]byte
	raw  RawSockaddrInet4
}

type RawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte /* in_addr */
	Zero   [8]uint8
}

type RawSockaddr struct {
	Family uint16
	Data   [14]int8
}

type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [100]int8
}

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, int32, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, syscall.EINVAL
	}
	sa.raw.Family = syscall.AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Addr[i] = sa.Addr[i]
	}
	return unsafe.Pointer(&sa.raw), int32(unsafe.Sizeof(sa.raw)), nil
}

func (rsa *RawSockaddrAny) Sockaddr() (Sockaddr, error) {
	pp := (*RawSockaddrInet4)(unsafe.Pointer(rsa))
	sa := new(SockaddrInet4)
	p := (*[2]byte)(unsafe.Pointer(&pp.Port))
	sa.Port = int(p[0])<<8 + int(p[1])
	for i := 0; i < len(sa.Addr); i++ {
		sa.Addr[i] = pp.Addr[i]
	}
	return sa, nil
}

func Recvfrom(fd Handle, p []byte, flags int) (n int, from Sockaddr, err error) {
	var rsa RawSockaddrAny
	l := int(unsafe.Sizeof(rsa))
	n32, e := recvfrom(fd, p, flags, &rsa, &l)
	if e != nil {
		return -1, nil, e
	}
	n = int(n32)
	from, err = rsa.Sockaddr()
	return
}

func Sendto(fd Handle, p []byte, flags int, to Sockaddr) (err error) {
	ptr, l, err := to.sockaddr()
	if err != nil {
		return err
	}
	return sendto(fd, p, flags, ptr, l)
}

func sendto(s Handle, buf []byte, flags int, to unsafe.Pointer, tolen int32) (err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r1, _, e1 := syscall.Syscall6(procsendto, 6, uintptr(s), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(flags), uintptr(to), uintptr(tolen))
	if r1 == uintptr(^uint32(0)) {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func recvfrom(s Handle, buf []byte, flags int, from *RawSockaddrAny, fromlen *int) (n int32, err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r0, _, e1 := syscall.Syscall6(procrecvfrom, 6, uintptr(s), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(flags), uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(fromlen)))
	n = int32(r0)
	if n == -1 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

func Socket(domain, typ, proto int) (fd Handle, err error) {
	return socket(int32(domain), int32(typ), int32(proto))
}

func socket(af int32, typ int32, protocol int32) (handle Handle, err error) {
	r0, _, e1 := syscall.Syscall(procsocket, 3, uintptr(af), uintptr(typ), uintptr(protocol))
	handle = Handle(r0)
	if handle == InvalidHandle {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
