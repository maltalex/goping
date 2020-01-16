# goping

A simple ping implementation in Go, written as a "Hello World" project.

This imlementation supports both **IPv4** and **IPv6** on both **Linux** and **Windows**,
as well as several command-line switches like `-t` (to set the TTL), `-s` to set the payload size,
`-W` to set the socket timeout, and others.

It's here as a reference for others, there's no good reason to actually use it. You have a perfectly good ping 
implementation in your OS, use that one.

## Lessons learned

- In hidnsight, not a great choice for a first project in Go. I've spent way too much time on dealing with different syscalls,
and too little time on Go.

- Windows support was especially hard since golang.org/x/sys simply didn't implement the necessary syscalls (`recvfrom`,`sendto`),
so I implemented them myself ([Pull Request #1](https://github.com/golang/sys/pull/46),
[Pull Request #2](https://github.com/golang/sys/pull/51)).
Even some of the standard constants like `IPPROTO_ICMP` were missing and had to be added
([Pull Request #3](https://github.com/golang/sys/pull/50), [Pull Request #4](https://github.com/golang/sys/pull/53))

- golang.org/x/sys/windows still lacks a lot of basic syscalls. Some just don't exist while others return `syscall.EWINDOWS`,
which means `not supported by windows`.

- IPv6 Raw sockets behave differently than IPv4 sockets. Most relevantly, an IPv6 raw socket doesn't allow the application
to send or receive the IPv6 header itself (See [RFC 3542](https://tools.ietf.org/html/rfc3542)). This means that to print 
the TTL (Hop Limit) field, one needs to use ancillary data, which is avaiable only using the `recvmsg` syscall.
Unsurprisingly, `recvmsg` and its send counterpart `sendmsg` aren't implemented in Windows, so that might be something more to 
do in the future. The current implementation uses `recvfrom`, so when pinging an IPv6 address, a TTL of 0 will be printed.
